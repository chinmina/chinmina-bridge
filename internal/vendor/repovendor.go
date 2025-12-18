package vendor

import (
	"context"
	"fmt"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/rs/zerolog/log"
)

// NewRepoVendor creates a vendor for pipeline-scoped (repo:*) profiles.
// Used by /token and /git-credentials routes.
// It uses the Buildkite API to find the pipeline's repository and vends
// tokens for that specific repository.
func NewRepoVendor(profileStore *profile.ProfileStore, repoLookup RepositoryLookup, tokenVendor TokenVendor) ProfileTokenVendor {
	return func(ctx context.Context, ref profile.ProfileRef, requestedRepoURL string) (*ProfileToken, error) {
		// Validate that this is a repo-scoped profile
		if ref.Type != profile.ProfileTypeRepo {
			return nil, fmt.Errorf("profile type mismatch: expected %s, got %s", profile.ProfileTypeRepo.String(), ref.Type.String())
		}

		// non-default repository-scoped profiles are not yet supported
		if ref.Name != profile.ProfileNameDefault {
			return nil, fmt.Errorf("unsupported profile name for repo-scoped profile: %s", ref.Name)
		}

		// Use Buildkite API to find the repository for the pipeline
		pipelineRepoURL, err := repoLookup(ctx, ref.Organization, ref.PipelineSlug)
		if err != nil {
			return nil, fmt.Errorf("could not find repository for pipeline %s: %w", ref.PipelineSlug, err)
		}

		logger := log.With().
			Str("organization", ref.Organization).
			Str("profile", ref.ShortString()).
			Str("repo", pipelineRepoURL).
			Logger()

		// The pipeline itself may be configured for SSH, and changed by the agent.
		// For comparison purposes here it has to be an HTTPS URL.
		pipelineRepoURL = TranslateSSHToHTTPS(pipelineRepoURL)

		if requestedRepoURL != "" && pipelineRepoURL != requestedRepoURL {
			// A repository mismatch means we should not return a token or an error:
			// Git uses this to determine that it should try the next provider.
			logger.Debug().
				Str("requestedRepo", requestedRepoURL).
				Msg("profile doesn't support requested repository: no token vended.")

			return nil, nil
		}

		allowedRepoNames, err := github.GetRepoNames([]string{pipelineRepoURL})
		if err != nil {
			return nil, fmt.Errorf("error getting repo names: %w", err)
		}
		if len(allowedRepoNames) == 0 {
			return nil, fmt.Errorf("no valid repository names found for URL: %s", pipelineRepoURL)
		}

		permissions := []string{"contents:read"} // fallback default
		// Get default permissions from organization config
		orgConfig, err := profileStore.GetOrganization()
		if err != nil {
			logger.Warn().Err(err).Msg("organization configuration not available, using fallback default permissions for repository token")
		} else {
			permissions = orgConfig.GetDefaultPermissions()
		}

		// Use the GitHub API to vend a token for the allowed repository
		token, expiry, err := tokenVendor(ctx, allowedRepoNames, permissions)
		if err != nil {
			return nil, fmt.Errorf("could not issue token for repository %s: %w", pipelineRepoURL, err)
		}

		return &ProfileToken{
			OrganizationSlug:    ref.Organization,
			VendedRepositoryURL: pipelineRepoURL,
			Repositories:        allowedRepoNames,
			Permissions:         permissions,
			Profile:             ref.ShortString(),
			Token:               token,
			Expiry:              expiry,
		}, nil
	}
}
