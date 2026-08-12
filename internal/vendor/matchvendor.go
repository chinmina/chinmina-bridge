package vendor

import (
	"context"
	"fmt"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

// MatcherLookup resolves the match rules gating a profile reference.
//
// Injected rather than switched on ref.Type: each route family serves exactly
// one profile type (see ProfileRef.AssertType), so the choice belongs in the
// wiring, and Matched stays free of profile-type knowledge.
type MatcherLookup func(profile.ProfileRef) (profile.Matcher, error)

// OrgMatcherLookup gates the /organization/* routes.
func OrgMatcherLookup(store *profile.ProfileStore) MatcherLookup {
	return func(ref profile.ProfileRef) (profile.Matcher, error) {
		if err := ref.AssertType(profile.ProfileTypeOrg); err != nil {
			return nil, err
		}

		authProfile, err := store.GetOrganizationProfile(ref.Name)
		if err != nil {
			return nil, fmt.Errorf("could not find profile %s: %w", ref.Name, err)
		}

		return authProfile.Match, nil
	}
}

// RepoMatcherLookup gates the /token and /git-credentials routes.
func RepoMatcherLookup(store *profile.ProfileStore) MatcherLookup {
	return func(ref profile.ProfileRef) (profile.Matcher, error) {
		if err := ref.AssertType(profile.ProfileTypeRepo); err != nil {
			return nil, err
		}

		authProfile, err := store.GetPipelineProfile(ref.Name)
		if err != nil {
			return nil, fmt.Errorf("could not find profile %s: %w", ref.Name, err)
		}

		return authProfile.Match, nil
	}
}

// Matched returns a decorator that evaluates a profile's match rules on
// every call to the wrapped vendor, cache hit or miss.
//
// Match-rule evaluation used to live inside NewOrgVendor and NewRepoVendor,
// but Cached short-circuits and returns a cached token before the wrapped
// vendor ever runs. That let any caller who could construct a ProfileRef
// already warmed in the cache receive that profile's token regardless of its
// match rules. Composing Matched outside Cached closes the gap: the gate runs
// on every request, so a cache hit can never bypass it.
func Matched(lookup MatcherLookup) func(ProfileTokenVendor) ProfileTokenVendor {
	return func(v ProfileTokenVendor) ProfileTokenVendor {
		return func(ctx context.Context, ref profile.ProfileRef, repo string) VendorResult {
			matcher, err := lookup(ref)
			if err != nil {
				return NewVendorFailed(err)
			}

			claims := profile.NewValidatingLookup(
				jwt.RequireBuildkiteClaimsFromContext(ctx),
			)
			result := AuditingMatcher(ctx, matcher)(claims)

			if result.Err != nil {
				return NewVendorFailed(fmt.Errorf("profile match evaluation failed: %w", result.Err))
			}
			if !result.Matched {
				return NewVendorFailed(profile.ProfileMatchFailedError{Name: ref.Name})
			}

			return v(ctx, ref, repo)
		}
	}
}
