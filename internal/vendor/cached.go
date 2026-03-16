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

func recordOutcome(ctx context.Context, result string) {
	initOutcomeMetrics()
	if tokenCacheOutcome == nil {
		return
	}
	tokenCacheOutcome.Add(ctx, 1,
		metric.WithAttributes(attribute.String("token.cache.result", result)),
	)
}

// Cached supplies a vendor that caches the results of the wrapped vendor. The
// cache is non-locking, and so concurrent requests for the same pipeline could
// cause multiple token requests, In this case, the last one returned wins. In
// this use case, given that concurrent calls are likely to be less common, the
// additional tokens issued are worth gains made skipping locking.
func Cached(tokenCache cache.TokenCache[ProfileToken], digester cache.Digester) func(ProfileTokenVendor) ProfileTokenVendor {
	return func(v ProfileTokenVendor) ProfileTokenVendor {
		return func(ctx context.Context, ref profile.ProfileRef, requestedRepository string) VendorResult {
			// Cache key includes digest prefix for config version namespacing
			key := fmt.Sprintf("%s:%s", digester.Digest(), ref.String())

			cachedToken, found, err := tokenCache.Get(ctx, key)
			if err != nil {
				// retrieval errors are effectively cache misses, but we record them
				// separately to identify cache issues in production
				recordOutcome(ctx, "error")
				slog.Warn("cache get failed", "error", err, "key", key)
			} else if !found {
				// successfully found that the key is not in the cache
				recordOutcome(ctx, "miss")
			} else if token, ok := checkTokenRepository(cachedToken, requestedRepository); !ok {
				recordOutcome(ctx, "mismatch")

				if ref.Type == profile.ProfileTypeOrg {
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
				recordOutcome(ctx, "hit")
				return NewVendorSuccess(token)
			}

			// cache miss: request and cache
			result := v(ctx, ref, requestedRepository)

			// Only cache successful results
			if token, tokenVended := result.Token(); tokenVended {
				if err := tokenCache.Set(ctx, key, token); err != nil {
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
