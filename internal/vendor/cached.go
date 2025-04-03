package vendor

import (
	"context"
	"fmt"
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
func Cached(ttl time.Duration) (func(ProfileTokenVendor) ProfileTokenVendor, error) {
	cache, err := otter.
		MustBuilder[string, ProfileToken](10_000).
		CollectStats().
		WithTTL(ttl).
		Build()
	if err != nil {
		return nil, err
	}

	return func(v ProfileTokenVendor) ProfileTokenVendor {
		return func(ctx context.Context, claims jwt.BuildkiteClaims, repo string, profile string) (*ProfileToken, error) {
			// Cache by profile. There are cases where profile is not used
			// (e.g. when vending a pipeline token), but we are using a URN
			// to solve this problem. This also allows us to support repo
			// level profiles in the future.
			// Structure:
			// - profile://org-name/<profile-type>/<profile/repo-name>/<profile-name>
			//
			// Examples:
			// - profile://org-name/organization/org-profile-name
			// - profile://org-name/pipeline/pipeline-name/default
			// - profile://org-name/pipeline/pipeline-name/write-packages
			var key string

			// Format the key based on the arguments passed.
			// If the profile is empty, we are vending a repo token, using the
			// default profile.
			// If the profile is not empty, we are vending a profile token.
			if profile == "" {
				profile = "default"
				key = fmt.Sprintf("profile://%s/pipeline/%s/%s", claims.OrganizationSlug, claims.PipelineID, profile)
			} else {
				key = fmt.Sprintf("profile://%s/organization/%s", claims.OrganizationSlug, profile)
			}

			// cache hit: return the cached token
			if cachedToken, ok := cache.Get(key); ok {
				log.Info().Time("expiry", cachedToken.Expiry).
					Str("key", key).
					Msg("hit: existing token found for pipeline")

				// if this is a profile token, we may need to update the repo
				// field for the in-flight value
				if repo == "" {
					cachedToken.RequestedRepositoryURL = repo
				}
				if cachedToken.RequestedRepositoryURL != repo {
					// Token invalid: remove from cache and fall through to reissue.
					// Re-cache likely to happen if the pipeline's repository was changed.
					log.Info().
						Str("key", key).Str("expected", repo).
						Str("actual", cachedToken.RequestedRepositoryURL).
						Msg("invalid: cached token issued for different repository")

					// the delete is required as "set" is not guaranteed to write to the cache
					cache.Delete(key)
				} else {
					return &cachedToken, nil
				}
			}

			// cache miss: request and cache
			token, err := v(ctx, claims, repo, profile)
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
