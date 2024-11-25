package vendor

import (
	"context"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/maypok86/otter"
	"github.com/rs/zerolog/log"
)

// Cached supplies a vendor that caches the results of the wrapped vendor. The
// cache is non-locking, and so concurrent requests for the same pipeline could
// cause multiple token requests, In this case, the last one returned wins. In
// this use case, given that concurrent calls are likely to be less common, the
// additional tokens issued are worth gains made skipping locking.
func Cached(ttl time.Duration) (func(PipelineTokenVendor) PipelineTokenVendor, error) {
	cache, err := otter.
		MustBuilder[string, PipelineRepositoryToken](10_000).
		CollectStats().
		WithTTL(ttl).
		Build()
	if err != nil {
		return nil, err
	}

	return func(v PipelineTokenVendor) PipelineTokenVendor {
		return func(ctx context.Context, claims jwt.BuildkiteClaims, repo string) (*PipelineRepositoryToken, error) {
			// Cache by pipeline: this allows token reuse across multiple
			// builds. It's likely that this will change if rules allow for
			// builds to be given different permissions based on the branch or
			// tag.
			key := claims.PipelineID

			if cachedToken, ok := cache.Get(key); ok {
				// The expected repo may be unknown, but if it's supplied it needs to
				// match the cached repo. An "unknown" means "give me the token for the
				// pipeline's repository"; when supplied, a token is request for a given
				// repo (if possible).
				if repo == "" || cachedToken.RepositoryURL == repo {
					log.Info().Time("expiry", cachedToken.Expiry).
						Str("key", key).
						Msg("hit: existing token found for pipeline")

					return &cachedToken, nil
				} else {
					// Token invalid: remove from cache and fall through to reissue.
					// Re-cache likely to happen if the pipeline's repository was changed.
					log.Info().
						Str("key", key).Str("expected", repo).
						Str("actual", cachedToken.RepositoryURL).
						Msg("invalid: cached token issued for different repository")

					// the delete is required as "set" is not guaranteed to write to the cache
					cache.Delete(key)
				}
			}

			// cache miss: request and cache
			token, err := v(ctx, claims, repo)
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
