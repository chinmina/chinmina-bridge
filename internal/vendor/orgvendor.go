package vendor

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

// NewOrgVendor creates a vendor for organization-scoped (org:*) profiles.
// Used by /organization/token/{profile} and /organization/git-credentials/{profile} routes.
// It vends tokens for a set of repositories defined in the profile configuration.
func NewOrgVendor(profileStore *profile.ProfileStore, tokenVendor TokenVendor) ProfileTokenVendor {
	return func(ctx context.Context, ref profile.ProfileRef, requestedRepoURL string, repositoryScope string) VendorResult {
		// Validate that this is an org-scoped profile
		if ref.Type != profile.ProfileTypeOrg {
			return NewVendorFailed(fmt.Errorf("profile type mismatch: expected %s, got %s", profile.ProfileTypeOrg.String(), ref.Type.String()))
		}

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

		// --- Bidirectional scoping validation ---
		profileScope := authProfile.Attrs.RepositoryScope()

		var repoScope profile.RepositoryScope

		if profileScope.IsCallerScoped() {
			if repositoryScope == "" {
				return NewVendorFailed(profile.RepositoryScopeRequiredError{ProfileName: ref.Name})
			}
			repoScope = profile.NewSpecificScope(repositoryScope)
		} else if repositoryScope != "" {
			return NewVendorFailed(profile.RepositoryScopeUnexpectedError{ProfileName: ref.Name})
		} else {
			repoScope = profileScope
		}

		// The repository is only supplied for the git-credentials endpoint:
		// checking it allows Git to respond properly: it's not a security measure.
		if requestedRepoURL != "" {
			repo, err := url.Parse(requestedRepoURL)
			if err != nil {
				return NewVendorFailed(fmt.Errorf("could not parse requested repo URL %s: %w", requestedRepoURL, err))
			}

			// Profiles that claim coverage of all repositories (wildcard or caller-scoped)
			// treat failure as a hard error — no credential helper fallback.
			// Static-list profiles return unmatched for repos outside their list.
			_, repository := github.RepoForURL(*repo)
			if !profileScope.IsWildcard() && !profileScope.IsCallerScoped() && !repoScope.Contains(repository) {
				slog.Debug("profile doesn't support requested repository: no token vended.",
					"organization", ref.Organization,
					"profile", ref.ShortString(),
					"requestedRepo", requestedRepoURL,
				)
				return NewVendorUnmatched()
			}
		}

		// Use the GitHub API to vend a token for the repository
		token, expiry, err := tokenVendor(ctx, repoScope.Names, authProfile.Attrs.Permissions)
		if err != nil {
			return NewVendorFailed(fmt.Errorf("could not issue token for profile %s: %w", ref, err))
		}

		slog.Info("profile token issued",
			"organization", ref.Organization,
			"profile", ref.ShortString(),
		)

		return NewVendorSuccess(ProfileToken{
			OrganizationSlug:    ref.Organization,
			VendedRepositoryURL: requestedRepoURL,
			Repositories:        repoScope,
			Permissions:         authProfile.Attrs.Permissions,
			Profile:             ref.ShortString(),
			Token:               token,
			HashedToken:         HashToken(token),
			Expiry:              expiry,
		})
	}
}
