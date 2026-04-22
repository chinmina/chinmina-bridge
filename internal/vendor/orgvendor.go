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
	return func(ctx context.Context, ref profile.ProfileRef, requestedRepoURL string) VendorResult {
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
		repoScope, err := resolveRequestScope(profileScope, ref)
		if err != nil {
			return NewVendorFailed(err)
		}

		// For non-caller-scoped profiles at the git-credentials endpoint,
		// check the requested repo against the profile's scope. Static-list
		// profiles return unmatched for repos outside their list; wildcard
		// profiles skip this check (they claim all repos).
		if requestedRepoURL != "" && !profileScope.IsCallerScoped() && !profileScope.IsWildcard() {
			repo, err := url.Parse(requestedRepoURL)
			if err != nil {
				return NewVendorFailed(fmt.Errorf("could not parse requested repo URL %s: %w", requestedRepoURL, err))
			}

			_, repository := github.RepoForURL(*repo)
			if !repoScope.Contains(repository) {
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

// resolveRequestScope determines the effective repository scope for a request.
// Scope validation happens at the handler boundary (in the ProfileRefBuilder);
// here we simply interpret the ref's ScopedRepository against the profile's
// declared scope. The builder is the single enforcement point, so this function
// only needs to read the already-validated ref and apply the profile's scope rules.
// For caller-scoped profiles, ScopedRepository is guaranteed non-empty by the builder.
func resolveRequestScope(profileScope profile.RepositoryScope, ref profile.ProfileRef) (profile.RepositoryScope, error) {
	if profileScope.IsCallerScoped() {
		// Builder guarantees ScopedRepository is non-empty for caller-scoped refs.
		return profile.NewSpecificScope(ref.ScopedRepository), nil
	}

	return profileScope, nil
}
