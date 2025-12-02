package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepoVendor_FailsWithWrongProfileType(t *testing.T) {
	v := vendor.NewRepoVendor(nil, nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeOrg, // Wrong type!
	}
	_, err := v(context.Background(), ref, "repo-url")
	require.ErrorContains(t, err, "profile type mismatch")
	require.ErrorContains(t, err, "repo")
	require.ErrorContains(t, err, "org")
}

func TestRepoVendor_FailsWithNonDefaultProfile(t *testing.T) {
	v := vendor.NewRepoVendor(nil, nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "custom-profile",
		Type:         profile.ProfileTypeRepo,
	}
	_, err := v(context.Background(), ref, "repo-url")
	require.ErrorContains(t, err, "unsupported profile name")
	require.ErrorContains(t, err, "custom-profile")
}

func TestRepoVendor_FailsWhenPipelineLookupFails(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "", errors.New("pipeline not found")
	})

	v := vendor.NewRepoVendor(repoLookup, nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	_, err := v(context.Background(), ref, "repo-url")
	require.ErrorContains(t, err, "could not find repository for pipeline")
}

func TestRepoVendor_SuccessfulNilOnRepoMismatch(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url-mismatch", nil
	})

	v := vendor.NewRepoVendor(repoLookup, nil)

	// When there is a difference between the requested repo (by Git generally)
	// and the repo associated with the pipeline, return success but empty.
	// This indicates that there are no credentials that can be issued.
	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	tok, err := v(context.Background(), ref, "https://github.com/org/other-repo")
	assert.NoError(t, err)
	assert.Nil(t, tok)
}

func TestRepoVendor_FailsWhenTokenVendorFails(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("token vendor failed")
	})

	v := vendor.NewRepoVendor(repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	tok, err := v(context.Background(), ref, "https://github.com/org/repo-url")
	assert.ErrorContains(t, err, "token vendor failed")
	assert.Nil(t, tok)
}

func TestRepoVendor_SucceedsWithTokenWhenPossible(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "vended-token-value", vendedDate, nil
	})

	v := vendor.NewRepoVendor(repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	tok, err := v(context.Background(), ref, "https://github.com/org/repo-url")
	assert.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "vended-token-value",
		Repositories:           []string{"repo-url"},
		Permissions:            []string{"contents:read"},
		Profile:                "repo:default",
		Expiry:                 vendedDate,
		OrganizationSlug:       "organization-slug",
		RequestedRepositoryURL: "https://github.com/org/repo-url",
	}, tok)
}

func TestRepoVendor_SucceedsWithEmptyRequestedRepo(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/pipeline-repo", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		// Verify that the token vendor receives the pipeline repo
		assert.Equal(t, []string{"pipeline-repo"}, repositoryURLs)
		return "vended-token-value", vendedDate, nil
	})

	v := vendor.NewRepoVendor(repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}

	// Empty requestedRepoURL should succeed by using pipeline repo
	tok, err := v(context.Background(), ref, "")
	assert.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "vended-token-value",
		Repositories:           []string{"pipeline-repo"},
		Permissions:            []string{"contents:read"},
		Profile:                "repo:default",
		Expiry:                 vendedDate,
		OrganizationSlug:       "organization-slug",
		RequestedRepositoryURL: "https://github.com/org/pipeline-repo",
	}, tok)
}

func TestRepoVendor_TranslatesSSHToHTTPSForPipelineRepo(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		// Return SSH URL from pipeline lookup
		return "git@github.com:org/repo-url.git", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "vended-token-value", vendedDate, nil
	})

	v := vendor.NewRepoVendor(repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// Request with HTTPS URL should match after translation
	tok, err := v(context.Background(), ref, "https://github.com/org/repo-url.git")
	assert.NoError(t, err)
	assert.NotNil(t, tok)
	assert.Equal(t, "https://github.com/org/repo-url.git", tok.RequestedRepositoryURL)
}
