package vendor

import (
	"context"
	"fmt"
	"slices"

	"github.com/chinmina/chinmina-bridge/internal/cache"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/rs/zerolog/log"
)

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
				log.Warn().Err(err).Str("key", key).Msg("cache get failed")
			} else if found {
				log.Debug().Time("expiry", cachedToken.Expiry).
					Str("key", key).
					Msg("hit: existing token found for pipeline")

				if token, ok := checkTokenRepository(cachedToken, requestedRepository); ok {
					return NewVendorSuccess(token)
				}

				log.Debug().
					Time("expiry", cachedToken.Expiry).
					Str("key", key).
					Str("requestedRepository", requestedRepository).
					Msg("dropping cached token due to repository mismatch: will request new token")

				// the delete is required as "set" is not guaranteed to write to the cache
				if err := tokenCache.Invalidate(ctx, key); err != nil {
					log.Warn().Err(err).Str("key", key).Msg("cache invalidate failed")
				}
			}

			// cache miss: request and cache
			result := v(ctx, ref, requestedRepository)

			// Only cache successful results
			if token, tokenVended := result.Token(); tokenVended {
				if err := tokenCache.Set(ctx, key, token); err != nil {
					log.Warn().Err(err).Str("key", key).Msg("cache set failed")
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

	// Extract repo name from the full URL before comparing
	repoNames, err := github.GetRepoNames([]string{requestedRepository})
	if err != nil || len(repoNames) == 0 {
		return ProfileToken{}, false
	}
	requestedRepoName := repoNames[0]

	if slices.Contains(cachedToken.Repositories, requestedRepoName) {
		cachedToken.VendedRepositoryURL = requestedRepository
		return cachedToken, true
	}

	return ProfileToken{}, false
}
