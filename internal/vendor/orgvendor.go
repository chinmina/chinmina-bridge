package vendor

import (
	"context"
	"fmt"
	"net/url"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/rs/zerolog/log"
)

// NewOrgVendor creates a vendor for organization-scoped (org:*) profiles.
// Used by /organization/token/{profile} and /organization/git-credentials/{profile} routes.
// It vends tokens for a set of repositories defined in the profile configuration.
func NewOrgVendor(profileStore *github.ProfileStore, tokenVendor TokenVendor) ProfileTokenVendor {
	return func(ctx context.Context, ref profile.ProfileRef, requestedRepoURL string) (*ProfileToken, error) {
		// Validate that this is an org-scoped profile
		if ref.Type != profile.ProfileTypeOrg {
			return nil, fmt.Errorf("profile type mismatch: expected %s, got %s", profile.ProfileTypeOrg.String(), ref.Type.String())
		}

		// Use the ProfileStore to get the requested profile and validate it
		profileConf, err := profileStore.GetProfileFromStore(ref.Name)
		if err != nil {
			log.Warn().Str("profile", ref.Name).Msg("requested profile was not found")
			return nil, fmt.Errorf("could not find profile %s: %w", ref.Name, err)
		}

		// If we receive an empty requested repository URL, this is a
		// naked token request. We will vend a token; this should not
		// be used as part of git-credential flows though.
		if requestedRepoURL == "" {
			log.Info().Str("organization", ref.Organization).
				Str("profile", ref.Name).
				Msg("raw token issued")

		} else {
			// Otherwise validate it against the profile.
			repo, err := url.Parse(requestedRepoURL)
			if err != nil {
				return nil, fmt.Errorf("could not parse requested repo URL %s: %w", requestedRepoURL, err)
			}

			// If the requested repository isn't in the profile, return nil.
			// This indicates that the handler should return a successful (but empty) response.
			_, repository := github.RepoForURL(*repo)
			if !profileConf.HasRepository(repository) {
				log.Warn().Str("repository", repository).Str("profile", ref.Name).Msg("requested repository was not found in profile")
				return nil, nil
			}
		}

		// Use the github api to vend a token for the repository
		token, expiry, err := tokenVendor(ctx, profileConf.Repositories, profileConf.Permissions)
		if err != nil {
			return nil, fmt.Errorf("could not issue token for repository %s: %w", requestedRepoURL, err)
		}

		log.Info().
			Str("organization", ref.Organization).
			Str("profile", ref.ShortString()).
			Str("repo", requestedRepoURL).
			Msg("profile token issued")

		return &ProfileToken{
			OrganizationSlug:       ref.Organization,
			RequestedRepositoryURL: requestedRepoURL,
			Repositories:           profileConf.Repositories,
			Permissions:            profileConf.Permissions,
			Profile:                ref.ShortString(),
			Token:                  token,
			Expiry:                 expiry,
		}, nil
	}
}
