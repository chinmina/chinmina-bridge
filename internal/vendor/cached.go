package vendor

import (
	"context"
	"slices"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/maypok86/otter/v2"
	"github.com/maypok86/otter/v2/stats"
	"github.com/rs/zerolog/log"
)

// Cached supplies a vendor that caches the results of the wrapped vendor. The
// cache is non-locking, and so concurrent requests for the same pipeline could
// cause multiple token requests, In this case, the last one returned wins. In
// this use case, given that concurrent calls are likely to be less common, the
// additional tokens issued are worth gains made skipping locking.
func Cached(ttl time.Duration) (func(ProfileTokenVendor) ProfileTokenVendor, error) {
	counter := stats.NewCounter()
	cache := otter.
		Must(&otter.Options[string, ProfileToken]{MaximumSize: 10_000, StatsRecorder: counter, ExpiryCalculator: otter.ExpiryCreating[string, ProfileToken](ttl)})

	return func(v ProfileTokenVendor) ProfileTokenVendor {
		return func(ctx context.Context, ref profile.ProfileRef, repo string) (*ProfileToken, error) {
			// Cache key is the URN format of the ProfileRef
			key := ref.String()

			// cache hit: return the cached token
			if cachedToken, ok := cache.GetEntry(key); ok {
				log.Info().Time("expiry", cachedToken.Value.Expiry).
					Str("key", key).
					Msg("hit: existing token found for pipeline")

				// There are a couple of cases where the repository may not match
				// the requested repository:
				// 1. The pipeline was created with a different repository, and
				// was changed.
				// 2. The token is a profile token, and was initially vended for
				// a different repository.
				if cachedToken.Value.VendedRepositoryURL != repo {
					// The profile token case:
					if slices.Contains(cachedToken.Value.Repositories, repo) {
						cachedToken.Value.VendedRepositoryURL = repo
						return &cachedToken.Value, nil
					} else {
						// The pipeline token case:
						// Token invalid: remove from cache and fall through to reissue.
						// Re-cache likely to happen if the pipeline's repository was changed.
						log.Info().
							Str("key", key).Str("expected", repo).
							Str("actual", cachedToken.Value.VendedRepositoryURL).
							Msg("invalid: cached token issued for different repository")

						// the delete is required as "set" is not guaranteed to write to the cache
						cache.Invalidate(key)
					}
				} else {
					return &cachedToken.Value, nil
				}
			}

			// cache miss: request and cache
			token, err := v(ctx, ref, repo)
			if err != nil {
				return nil, err
			}

			// token can be nil if the vendor wishes to indicate that there's neither
			// a token nor an error
			if token != nil {
				cache.Set(key, *token)
			}

			return token, nil
		}
	}, nil
}
