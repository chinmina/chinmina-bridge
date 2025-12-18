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

func createProfileStoreWithPermissions(permissions []string) *profile.ProfileStore {
	ps := profile.NewProfileStore()
	config := profile.ProfileConfig{}
	config.Organization.Defaults.Permissions = permissions
	config.Organization.Profiles = []profile.Profile{{Name: "default"}}
	ps.Update(config)
	return ps
}

func createProfileStoreWithError() *profile.ProfileStore {
	return profile.NewProfileStore()
}

func TestRepoVendor_FailsWithWrongProfileType(t *testing.T) {
	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{"contents:read"}), nil, nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeOrg, // Wrong type!
		PipelineSlug: "",
	}
	_, err := v(context.Background(), ref, "repo-url")
	require.ErrorContains(t, err, "profile type mismatch")
	require.ErrorContains(t, err, "repo")
	require.ErrorContains(t, err, "org")
}

func TestRepoVendor_FailsWithNonDefaultProfile(t *testing.T) {
	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{"contents:read"}), nil, nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "custom-profile",
		Type:         profile.ProfileTypeRepo,
		PipelineSlug: "my-pipeline",
	}
	_, err := v(context.Background(), ref, "repo-url")
	require.ErrorContains(t, err, "unsupported profile name")
	require.ErrorContains(t, err, "custom-profile")
}

func TestRepoVendor_FailsWhenPipelineLookupFails(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "", errors.New("pipeline not found")
	})

	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{"contents:read"}), repoLookup, nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	_, err := v(context.Background(), ref, "repo-url")
	require.ErrorContains(t, err, "could not find repository for pipeline")
}

func TestRepoVendor_FailsWhenNoValidRepoNames(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		// Return a URL that will fail repo name extraction
		return "https://github.com/", nil
	})

	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{"contents:read"}), repoLookup, nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	_, err := v(context.Background(), ref, "")
	require.ErrorContains(t, err, "error getting repo names")
	require.ErrorContains(t, err, "no valid repository URLs found")
}

func TestRepoVendor_SuccessfulNilOnRepoMismatch(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url-mismatch", nil
	})

	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{"contents:read"}), repoLookup, nil)

	// When there is a difference between the requested repo (by Git generally)
	// and the repo associated with the pipeline, return success but empty.
	// This indicates that there are no credentials that can be issued.
	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
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

	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{"contents:read"}), repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
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

	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{"contents:read"}), repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
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

	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{"contents:read"}), repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
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

	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{"contents:read"}), repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	// Request with HTTPS URL should match after translation
	tok, err := v(context.Background(), ref, "https://github.com/org/repo-url.git")
	assert.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "vended-token-value",
		Repositories:           []string{"repo-url"},
		Permissions:            []string{"contents:read"},
		Profile:                "repo:default",
		Expiry:                 vendedDate,
		OrganizationSlug:       "organization-slug",
		RequestedRepositoryURL: "https://github.com/org/repo-url.git",
	}, tok)
}

func TestRepoVendor_UsesConfiguredPermissionsFromProfileStore(t *testing.T) {
	vendedDate := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url.git", nil
	})

	var capturedPermissions []string
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, permissions []string) (string, time.Time, error) {
		capturedPermissions = permissions
		return "vended-token-value", vendedDate, nil
	})

	configuredPermissions := []string{"contents:read", "pull_requests:write", "actions:read"}
	v := vendor.NewRepoVendor(createProfileStoreWithPermissions(configuredPermissions), repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	tok, err := v(context.Background(), ref, "")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "vended-token-value",
		Repositories:           []string{"repo-url"},
		Permissions:            configuredPermissions,
		Profile:                "repo:default",
		Expiry:                 vendedDate,
		OrganizationSlug:       "organization-slug",
		RequestedRepositoryURL: "https://github.com/org/repo-url.git",
	}, tok)
	// Verify configured permissions were used in token vendor call
	assert.Equal(t, configuredPermissions, capturedPermissions)
}

func TestRepoVendor_FallbackPermissionsOnProfileStoreError(t *testing.T) {
	vendedDate := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url.git", nil
	})

	var capturedPermissions []string
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, permissions []string) (string, time.Time, error) {
		capturedPermissions = permissions
		return "vended-token-value", vendedDate, nil
	})

	// ProfileStore with error (no config loaded)
	v := vendor.NewRepoVendor(createProfileStoreWithError(), repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	tok, err := v(context.Background(), ref, "")
	require.NoError(t, err)
	require.NotNil(t, tok)

	// Verify fallback permissions were used
	fallbackPermissions := []string{"contents:read"}
	assert.Equal(t, fallbackPermissions, capturedPermissions)
	assert.Equal(t, fallbackPermissions, tok.Permissions)
}

func TestRepoVendor_MultiplePermissionsAreIncludedInResponse(t *testing.T) {
	vendedDate := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url.git", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, permissions []string) (string, time.Time, error) {
		return "vended-token-value", vendedDate, nil
	})

	multiplePermissions := []string{"contents:read", "pull_requests:read", "issues:read", "statuses:write"}
	v := vendor.NewRepoVendor(createProfileStoreWithPermissions(multiplePermissions), repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	tok, err := v(context.Background(), ref, "")
	require.NoError(t, err)
	require.NotNil(t, tok)

	// Verify all permissions are included and order is maintained
	assert.Equal(t, multiplePermissions, tok.Permissions)
}

func TestRepoVendor_EmptyDefaultPermissionsUsesFallback(t *testing.T) {
	vendedDate := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url.git", nil
	})

	var capturedPermissions []string
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, permissions []string) (string, time.Time, error) {
		capturedPermissions = permissions
		return "vended-token-value", vendedDate, nil
	})

	// Explicitly empty permissions array (backward compatibility case)
	v := vendor.NewRepoVendor(createProfileStoreWithPermissions([]string{}), repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	tok, err := v(context.Background(), ref, "")
	require.NoError(t, err)
	require.NotNil(t, tok)

	// Verify fallback is used when defaults are empty
	fallbackPermissions := []string{"contents:read"}
	assert.Equal(t, fallbackPermissions, capturedPermissions)
	assert.Equal(t, fallbackPermissions, tok.Permissions)
}
