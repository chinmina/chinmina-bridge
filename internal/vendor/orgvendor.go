package vendor

import (
	"context"
	"fmt"
	"net/url"
	"slices"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/rs/zerolog/log"
)

// NewOrgVendor creates a vendor for organization-scoped (org:*) profiles.
// Used by /organization/token/{profile} and /organization/git-credentials/{profile} routes.
// It vends tokens for a set of repositories defined in the profile configuration.
func NewOrgVendor(profileStore *profile.ProfileStore, tokenVendor TokenVendor) ProfileTokenVendor {
	return func(ctx context.Context, ref profile.ProfileRef, requestedRepoURL string) VendorResult {
		// Validate that this is an org-scoped profile
		if ref.Type != profile.ProfileTypeOrg {
			return NewVendorFailed(fmt.Errorf("profile type mismatch: expected %s, got %s", profile.ProfileTypeOrg.String(), ref.Type.String()))
		}

		logger := log.With().
			Str("organization", ref.Organization).
			Str("profile", ref.ShortString()).
			Str("requestedRepo", requestedRepoURL).
			Logger()

		// Use the ProfileStore to get the requested profile and validate it
		authProfile, err := profileStore.GetOrganizationProfile(ref.Name)
		if err != nil {
			return NewVendorFailed(fmt.Errorf("could not find profile %s: %w", ref.Name, err))
		}

		profileMatcher := AuditingMatcher(ctx, authProfile.Match)

		// Evaluate match conditions against JWT claims, validating as we go
		claims := profile.NewValidatingLookup(
			jwt.RequireBuildkiteClaimsFromContext(ctx),
		)
		result := profileMatcher(claims)

		// TODO: this needs to be double-checked: it seems pretty clunky. We need to
		// make sure that the way this is dealt with is correct, and probably change
		// the MatchResult so the API shows its meaning by how it's structured.
		if result.Err != nil {
			// Return validation errors or other errors directly
			return NewVendorFailed(fmt.Errorf("profile match evaluation failed: %w", result.Err))
		}
		if !result.Matched {
			// Match conditions not met
			return NewVendorFailed(profile.ProfileMatchFailedError{Name: ref.Name})
		}

		// The repository is only supplied for the git-credentials endpoint:
		// checking it allows Git to respond properly: it's not a security measure.
		if requestedRepoURL != "" {
			// Otherwise validate it against the profile.
			repo, err := url.Parse(requestedRepoURL)
			if err != nil {
				return NewVendorFailed(fmt.Errorf("could not parse requested repo URL %s: %w", requestedRepoURL, err))
			}

			// If the requested repository isn't in the profile, return nil. This
			// indicates that the handler should return a successful (but empty)
			// response. This allows Git (for example) to try a different provider in
			// its credentials chain.
			_, repository := github.RepoForURL(*repo)
			if !slices.Contains(authProfile.Attrs.Repositories, repository) {
				logger.Debug().Msg("profile doesn't support requested repository: no token vended.")
				return NewVendorUnmatched()
			}
		}

		// Use the GitHub API to vend a token for the repository
		token, expiry, err := tokenVendor(ctx, authProfile.Attrs.Repositories, authProfile.Attrs.Permissions)
		if err != nil {
			return NewVendorFailed(fmt.Errorf("could not issue token for profile %s: %w", ref, err))
		}

		logger.Info().Msg("profile token issued")

		return NewVendorSuccess(ProfileToken{
			OrganizationSlug:    ref.Organization,
			VendedRepositoryURL: requestedRepoURL,
			Repositories:        authProfile.Attrs.Repositories,
			Permissions:         authProfile.Attrs.Permissions,
			Profile:             ref.ShortString(),
			Token:               token,
			Expiry:              expiry,
		})
	}
}
