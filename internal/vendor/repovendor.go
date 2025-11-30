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
func NewRepoVendor(repoLookup RepositoryLookup, tokenVendor TokenVendor) ProfileTokenVendor {
	return func(ctx context.Context, ref profile.ProfileRef, requestedRepoURL string) (*ProfileToken, error) {
		// Validate that this is a repo-scoped profile
		if ref.Type != profile.ProfileTypeRepo {
			return nil, fmt.Errorf("profile type mismatch: expected %s, got %s", profile.ProfileTypeRepo.String(), ref.Type.String())
		}

		// Use buildkite api to find the repository for the pipeline
		pipelineRepoURL, err := repoLookup(ctx, ref.Organization, ref.PipelineID)
		if err != nil {
			return nil, fmt.Errorf("could not find repository for pipeline %s: %w", ref.PipelineID, err)
		}

		// Allow HTTPS credentials if the pipeline is configured for an equivalent SSH URL
		pipelineRepoURL = TranslateSSHToHTTPS(pipelineRepoURL)

		if requestedRepoURL != "" && pipelineRepoURL != requestedRepoURL {
			// git is asking for a different repo than we can handle: return nil
			// to indicate that the handler should return a successful (but empty) response.
			log.Info().Msgf("no token issued: repo mismatch. pipeline(%s) != requested(%s)", pipelineRepoURL, requestedRepoURL)
			return nil, nil
		}

		requestedRepo, err := github.GetRepoNames([]string{requestedRepoURL})
		if err != nil {
			return nil, fmt.Errorf("error getting repo names: %w", err)
		}

		// Use the github api to vend a token for the repository
		token, expiry, err := tokenVendor(ctx, requestedRepo, []string{"contents:read"})
		if err != nil {
			return nil, fmt.Errorf("could not issue token for repository %s: %w", pipelineRepoURL, err)
		}

		log.Info().
			Str("organization", ref.Organization).
			Str("profile", ref.ShortString()).
			Str("repo", requestedRepoURL).
			Msg("token issued")

		return &ProfileToken{
			OrganizationSlug:       ref.Organization,
			RequestedRepositoryURL: pipelineRepoURL,
			Repositories:           requestedRepo,
			Permissions:            []string{"contents:read"},
			Profile:                ref.ShortString(),
			Token:                  token,
			Expiry:                 expiry,
		}, nil
	}
}
