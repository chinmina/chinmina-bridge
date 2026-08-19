package vendor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/chinmina/chinmina-bridge/internal/cache"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	outcomeMetricsOnce sync.Once
	tokenCacheOutcome  metric.Int64Counter
)

func initOutcomeMetrics() {
	outcomeMetricsOnce.Do(func() {
		meter := otel.Meter("github.com/chinmina/chinmina-bridge/internal/vendor")

		var err error
		tokenCacheOutcome, err = meter.Int64Counter(
			"token.cache.outcome",
			metric.WithDescription("Token cache lookup outcomes"),
		)
		if err != nil {
			otel.Handle(err)
		}
	})
}

func recordOutcome(ctx context.Context, result string, appName string) {
	initOutcomeMetrics()
	if tokenCacheOutcome == nil {
		return
	}
	tokenCacheOutcome.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("token.cache.result", result),
			attribute.String("token.app", appName),
		),
	)
}

// cacheKey identifies a cached token by configuration generation, minting app
// identity, and profile.
//
// The identity must be in the key: the mapping from an app name to a
// credential lives in deployment configuration, so repointing a name leaves
// the YAML — and its digest — unchanged while the cache still holds tokens
// minted through the previous app. Keying on the identity rather than the name
// means two names for one application and installation share entries.
//
// Numeric identifiers cannot contain the separator, so the key is unambiguous.
// Changing this format orphans every existing entry; nothing reaps them, they
// expire.
func cacheKey[T any](r Resolved[T]) string {
	return fmt.Sprintf("%s:%d:%d:%s", r.Digest, r.App.ApplicationID, r.App.InstallationID, r.Ref.String())
}

// Cached supplies a vendor that caches the results of the wrapped vendor. The
// cache is non-locking, and so concurrent requests for the same pipeline could
// cause multiple token requests, In this case, the last one returned wins. In
// this use case, given that concurrent calls are likely to be less common, the
// additional tokens issued are worth gains made skipping locking.
func Cached[T any](tokenCache cache.TokenCache[ProfileToken]) func(ProfileTokenVendor[T]) ProfileTokenVendor[T] {
	return func(v ProfileTokenVendor[T]) ProfileTokenVendor[T] {
		return func(ctx context.Context, r Resolved[T], requestedRepository string) VendorResult {
			// Namespace the key by configuration generation so entries from
			// different generations never collide; refuse rather than assume
			// an unresolved digest.
			if r.Digest == "" {
				return NewVendorFailed(fmt.Errorf("no configuration generation resolved for profile %s", r.Ref))
			}

			// Refuse rather than assuming the default app.
			if r.App.IsZero() {
				return NewVendorFailed(fmt.Errorf("no app identity resolved for profile %s", r.Ref))
			}

			key := cacheKey(r)

			cachedToken, found, err := tokenCache.Get(ctx, key)
			if err != nil {
				// retrieval errors are effectively cache misses, but we record them
				// separately to identify cache issues in production
				recordOutcome(ctx, "error", r.App.Name)
				slog.Warn("cache get failed", "error", err, "key", key)
			} else if !found {
				// successfully found that the key is not in the cache
				recordOutcome(ctx, "miss", r.App.Name)
			} else if token, ok := checkTokenRepository(cachedToken, requestedRepository); !ok {
				recordOutcome(ctx, "mismatch", r.App.Name)

				if r.Ref.Type == profile.ProfileTypeOrg {
					// For org profiles, a mismatch means the request is for a repo not
					// in the profile's configured list. The cached token is still valid
					// for other repos — don't invalidate it. The vendor will return
					// Unmatched for this request.
					slog.Debug("repository mismatch (organization profile): fall back to requesting a new token. Cache entry preserved.",
						"key", key,
						"requestedRepository", requestedRepository,
						"cachedRepositories", cachedToken.Repositories,
					)
				} else {
					// For repo profiles, a mismatch may indicate the pipeline's
					// repository has changed. Invalidate the stale entry.
					slog.Debug("repository mismatch (pipeline profile): fall back to requesting a new token. Cache entry invalidated.",
						"expiry", cachedToken.Expiry,
						"key", key,
						"requestedRepository", requestedRepository,
						"cachedRepositories", cachedToken.Repositories,
					)

					// forced invalidation is more effective than setting the value to be
					// empty -- some caches don't guarantee writes.
					if err := tokenCache.Invalidate(ctx, key); err != nil {
						slog.Warn("cache invalidate failed", "error", err, "key", key)
					}
				}
			} else {
				// short circuit and return on a cache hit
				recordOutcome(ctx, "hit", r.App.Name)
				return NewVendorSuccess(token)
			}

			// cache miss: request and cache
			result := v(ctx, r, requestedRepository)

			// Only cache successful results
			if result.Status() == VendStatusSuccess {
				if err := tokenCache.Set(ctx, key, result.Token()); err != nil {
					slog.Warn("cache set failed", "error", err, "key", key)
				}
			}

			return result
		}
	}
}

func checkTokenRepository(cachedToken ProfileToken, requestedRepository string) (ProfileToken, bool) {

	//
	// Note that the requested repository is only valued for Git credentials
	// requests.
	//

	// There is a small chance that a pipeline's repository could change, leading
	// to a cached token for the wrong repository. We reduce the chance of this
	// for Git credentials requests by checking the repository and invalidating
	// the cache when it's not valid.
	//
	// For non-Git credentials requests, we always return the cached token until
	// it expires. There is an impedance mismatch here between what the cache
	// stores (a token for a repository) vs what's authenticated (the pipeline).

	if requestedRepository == "" { // not a Git credentials request, no repo
		return cachedToken, true
	}

	// Wildcard scope covers all repositories
	if cachedToken.Repositories.IsWildcard() {
		cachedToken.VendedRepositoryURL = requestedRepository
		return cachedToken, true
	}

	// Extract repo name from the full URL before comparing
	repoNames, err := github.GetRepoNames([]string{requestedRepository})
	if err != nil || len(repoNames) == 0 {
		return ProfileToken{}, false
	}
	requestedRepoName := repoNames[0]

	if cachedToken.Repositories.Contains(requestedRepoName) {
		cachedToken.VendedRepositoryURL = requestedRepository
		return cachedToken, true
	}

	return ProfileToken{}, false
}
