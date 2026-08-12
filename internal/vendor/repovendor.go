package vendor

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

// NewRepoVendor creates a vendor for pipeline-scoped (repo:*) profiles.
// Used by /token and /git-credentials routes.
// It uses the Buildkite API to find the pipeline's repository and vends
// tokens for that specific repository.
func NewRepoVendor(profileStore *profile.ProfileStore, repoLookup RepositoryLookup, tokenVendor TokenVendor) ProfileTokenVendor[profile.PipelineProfileAttr] {
	return func(ctx context.Context, r Resolved[profile.PipelineProfileAttr], requestedRepoURL string) VendorResult {
		ref := r.Ref

		// Use Buildkite API to find the repository for the pipeline
		pipelineRepoURL, err := repoLookup(ctx, ref.Organization, ref.PipelineSlug)
		if err != nil {
			return NewVendorFailed(fmt.Errorf("could not find repository for pipeline %s: %w", ref.PipelineSlug, err))
		}

		// The pipeline itself may be configured for SSH, and changed by the agent.
		// For comparison purposes here it has to be an HTTPS URL.
		pipelineRepoURL = TranslateSSHToHTTPS(pipelineRepoURL)

		if requestedRepoURL != "" && pipelineRepoURL != requestedRepoURL {
			// A repository mismatch means we should not return a token or an error:
			// Git uses this to determine that it should try the next provider.
			slog.Debug("profile doesn't support requested repository: no token vended.",
				"organization", ref.Organization,
				"profile", ref.ShortString(),
				"repo", pipelineRepoURL,
				"requestedRepo", requestedRepoURL,
			)

			return NewVendorUnmatched()
		}

		allowedRepoNames, err := github.GetRepoNames([]string{pipelineRepoURL})
		if err != nil {
			return NewVendorFailed(fmt.Errorf("error getting repo names: %w", err))
		}
		if len(allowedRepoNames) == 0 {
			return NewVendorFailed(fmt.Errorf("no valid repository names found for URL: %s", pipelineRepoURL))
		}

		// Get pipeline profile (simple lookup - "default" is in the map)
		pipelineProfile, _, err := profileStore.GetPipelineProfile(ref.Name)
		if err != nil {
			return NewVendorFailed(fmt.Errorf("could not find pipeline profile %s: %w", ref.Name, err))
		}

		permissions := pipelineProfile.Attrs.Permissions

		// Use the GitHub API to vend a token for the allowed repository
		token, expiry, err := tokenVendor(ctx, allowedRepoNames, permissions)
		if err != nil {
			return NewVendorFailed(fmt.Errorf("could not issue token for repository %s: %w", pipelineRepoURL, err))
		}

		return NewVendorSuccess(ProfileToken{
			OrganizationSlug:    ref.Organization,
			VendedRepositoryURL: pipelineRepoURL,
			Repositories:        profile.NewSpecificScope(allowedRepoNames...),
			Permissions:         permissions,
			Profile:             ref.ShortString(),
			Token:               token,
			HashedToken:         HashToken(token),
			Expiry:              expiry,
		})
	}
}
