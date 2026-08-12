package vendor_test

import (
	"context"
	_ "embed"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/profile/profiletest"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata/defaults.yaml
var defaultPermissionsYAML string

//go:embed testdata/multiple-permissions.yaml
var multiplePermissionsYAML string

//go:embed testdata/multiple-permissions-extended.yaml
var multiplePermissionsExtendedYAML string

//go:embed testdata/pipeline-profiles.yaml
var pipelineProfilesYAML string

func TestRepoVendor_FailsWhenPipelineLookupFails(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "", errors.New("pipeline not found")
	})

	store := profiletest.CreateTestProfileStore(t, defaultPermissionsYAML)
	v := vendor.NewRepoVendor(store, repoLookup, nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "repo-url")
	assertVendorFailure(t, result, "could not find repository for pipeline")
}

func TestRepoVendor_FailsWhenNoValidRepoNames(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		// Return a URL that will fail repo name extraction
		return "https://github.com/", nil
	})

	store := profiletest.CreateTestProfileStore(t, defaultPermissionsYAML)
	v := vendor.NewRepoVendor(store, repoLookup, nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "")
	assertVendorFailure(t, result, "error getting repo names")
}

func TestRepoVendor_SuccessfulNilOnRepoMismatch(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url-mismatch", nil
	})

	store := profiletest.CreateTestProfileStore(t, defaultPermissionsYAML)
	v := vendor.NewRepoVendor(store, repoLookup, nil)

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
	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "https://github.com/org/other-repo")
	assertVendorUnmatched(t, result)
}

func TestRepoVendor_FailsWhenTokenVendorFails(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("token vendor failed")
	})

	store := profiletest.CreateTestProfileStore(t, defaultPermissionsYAML)
	v := vendor.NewRepoVendor(store, repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "https://github.com/org/repo-url")
	assertVendorFailure(t, result, "token vendor failed")
}

func TestRepoVendor_SucceedsWithTokenWhenPossible(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "vended-token-value", vendedDate, nil
	})

	store := profiletest.CreateTestProfileStore(t, defaultPermissionsYAML)
	v := vendor.NewRepoVendor(store, repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "https://github.com/org/repo-url")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "vended-token-value",
		HashedToken:         vendor.HashToken("vended-token-value"),
		Repositories:        profile.NewSpecificScope("repo-url"),
		Permissions:         []string{"contents:read", "metadata:read"},
		Profile:             "repo:default",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "https://github.com/org/repo-url",
	})
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

	store := profiletest.CreateTestProfileStore(t, defaultPermissionsYAML)
	v := vendor.NewRepoVendor(store, repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	// Empty requestedRepoURL should succeed by using pipeline repo
	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "vended-token-value",
		HashedToken:         vendor.HashToken("vended-token-value"),
		Repositories:        profile.NewSpecificScope("pipeline-repo"),
		Permissions:         []string{"contents:read", "metadata:read"},
		Profile:             "repo:default",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "https://github.com/org/pipeline-repo",
	})
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

	store := profiletest.CreateTestProfileStore(t, defaultPermissionsYAML)
	v := vendor.NewRepoVendor(store, repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	// Request with HTTPS URL should match after translation
	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "https://github.com/org/repo-url.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "vended-token-value",
		HashedToken:         vendor.HashToken("vended-token-value"),
		Repositories:        profile.NewSpecificScope("repo-url"),
		Permissions:         []string{"contents:read", "metadata:read"},
		Profile:             "repo:default",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "https://github.com/org/repo-url.git",
	})
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

	configuredPermissions := []string{"contents:read", "pull_requests:write", "actions:read", "metadata:read"}
	store := profiletest.CreateTestProfileStore(t, multiplePermissionsYAML)
	v := vendor.NewRepoVendor(store, repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "vended-token-value",
		HashedToken:         vendor.HashToken("vended-token-value"),
		Repositories:        profile.NewSpecificScope("repo-url"),
		Permissions:         configuredPermissions,
		Profile:             "repo:default",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "https://github.com/org/repo-url.git",
	})
	// Verify configured permissions were used in token vendor call
	assert.Equal(t, configuredPermissions, capturedPermissions)
}

func TestRepoVendor_FailsWhenProfileStoreNotLoaded(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url.git", nil
	})

	// ProfileStore with no config loaded
	v := vendor.NewRepoVendor(profile.NewProfileStore(), repoLookup, nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), vendor.Resolved[profile.PipelineProfileAttr]{Ref: ref}, "")
	assertVendorFailure(t, result, "could not find pipeline profile")
}

func TestRepoVendor_MultiplePermissionsAreIncludedInResponse(t *testing.T) {
	vendedDate := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url.git", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, permissions []string) (string, time.Time, error) {
		return "vended-token-value", vendedDate, nil
	})

	multiplePermissions := []string{"contents:read", "pull_requests:read", "issues:read", "statuses:write", "metadata:read"}
	store := profiletest.CreateTestProfileStore(t, multiplePermissionsExtendedYAML)
	v := vendor.NewRepoVendor(store, repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "vended-token-value",
		HashedToken:         vendor.HashToken("vended-token-value"),
		Repositories:        profile.NewSpecificScope("repo-url"),
		Permissions:         multiplePermissions,
		Profile:             "repo:default",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "https://github.com/org/repo-url.git",
	})
}

func TestRepoVendor_NamedProfileLookupSuccess(t *testing.T) {
	vendedDate := time.Date(1990, 01, 01, 0, 0, 0, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})

	var capturedPermissions []string
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, permissions []string) (string, time.Time, error) {
		capturedPermissions = permissions
		return "vended-token-value", vendedDate, nil
	})

	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	v := vendor.NewRepoVendor(store, repoLookup, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "high-access",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolvedPipeline(t, store, ref), "")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "vended-token-value",
		HashedToken:         vendor.HashToken("vended-token-value"),
		Repositories:        profile.NewSpecificScope("repo-url"),
		Permissions:         []string{"contents:write", "pull_requests:write", "metadata:read"},
		Profile:             "repo:high-access",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "https://github.com/org/repo-url",
	})
	// Verify the high-access profile permissions were used
	assert.Equal(t, []string{"contents:write", "pull_requests:write", "metadata:read"}, capturedPermissions)
}

func TestRepoVendor_ProfileNotFound(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})

	v := vendor.NewRepoVendor(profiletest.CreateTestProfileStore(t, pipelineProfilesYAML), repoLookup, nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "nonexistent-profile",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), vendor.Resolved[profile.PipelineProfileAttr]{Ref: ref}, "")
	assertVendorFailure(t, result, "could not find pipeline profile")
}
