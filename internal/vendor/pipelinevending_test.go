package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
)

// defaultPipelinePermissions is what the profile store produced for the
// pipeline default profile: the configured contents:read plus the implicit
// metadata:read.
var defaultPipelinePermissions = []string{"contents:read", "metadata:read"}

func TestPipelineVending_FailsWhenPipelineLookupFails(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "", errors.New("pipeline not found")
	})

	v := vendor.Vending(vendor.PipelineRepositories(repoLookup), nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	resolved := pipelineResolved(ref, profile.PipelineProfileAttr{Permissions: defaultPipelinePermissions})

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolved, "repo-url")
	assertVendorFailure(t, result, "could not find repository for pipeline")
}

func TestPipelineVending_FailsWhenNoValidRepoNames(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		// Return a URL that will fail repo name extraction
		return "https://github.com/", nil
	})

	v := vendor.Vending(vendor.PipelineRepositories(repoLookup), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	resolved := pipelineResolved(ref, profile.PipelineProfileAttr{Permissions: defaultPipelinePermissions})

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolved, "")
	assertVendorFailure(t, result, "error getting repo names")
}

func TestPipelineVending_SuccessfulNilOnRepoMismatch(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url-mismatch", nil
	})

	v := vendor.Vending(vendor.PipelineRepositories(repoLookup), nil)

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
	resolved := pipelineResolved(ref, profile.PipelineProfileAttr{Permissions: defaultPipelinePermissions})

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolved, "https://github.com/org/other-repo")
	assertVendorUnmatched(t, result)
}

func TestPipelineVending_FailsWhenTokenVendorFails(t *testing.T) {
	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("token vendor failed")
	})

	v := vendor.Vending(vendor.PipelineRepositories(repoLookup), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	resolved := pipelineResolved(ref, profile.PipelineProfileAttr{Permissions: defaultPipelinePermissions})

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolved, "https://github.com/org/repo-url")
	assertVendorFailure(t, result, "token vendor failed")
}

func TestPipelineVending_SucceedsWithTokenWhenPossible(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "vended-token-value", vendedDate, nil
	})

	v := vendor.Vending(vendor.PipelineRepositories(repoLookup), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	resolved := pipelineResolved(ref, profile.PipelineProfileAttr{Permissions: defaultPipelinePermissions})

	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolved, "https://github.com/org/repo-url")
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

func TestPipelineVending_SucceedsWithEmptyRequestedRepo(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/pipeline-repo", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		// Verify that the token vendor receives the pipeline repo
		assert.Equal(t, []string{"pipeline-repo"}, repositoryURLs)
		return "vended-token-value", vendedDate, nil
	})

	v := vendor.Vending(vendor.PipelineRepositories(repoLookup), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	resolved := pipelineResolved(ref, profile.PipelineProfileAttr{Permissions: defaultPipelinePermissions})

	// Empty requestedRepoURL should succeed by using pipeline repo
	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolved, "")
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

func TestPipelineVending_TranslatesSSHToHTTPSForPipelineRepo(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		// Return SSH URL from pipeline lookup
		return "git@github.com:org/repo-url.git", nil
	})

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "vended-token-value", vendedDate, nil
	})

	v := vendor.Vending(vendor.PipelineRepositories(repoLookup), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	resolved := pipelineResolved(ref, profile.PipelineProfileAttr{Permissions: defaultPipelinePermissions})

	// Request with HTTPS URL should match after translation
	result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolved, "https://github.com/org/repo-url.git")
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

// TestPipelineVending_IssuesTheResolvedProfilesPermissions checks that
// whatever permission set arrives on the resolved profile is what the token
// is minted with and what the response reports. Vending performs no lookup
// of its own, so the profile name is incidental — only the permissions it
// carried matter.
func TestPipelineVending_IssuesTheResolvedProfilesPermissions(t *testing.T) {
	vendedDate := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name        string
		profileName string
		permissions []string
	}{
		{
			name:        "default profile",
			profileName: "default",
			permissions: defaultPipelinePermissions,
		},
		{
			name:        "several permissions",
			profileName: "default",
			permissions: []string{"contents:read", "pull_requests:write", "actions:read", "metadata:read"},
		},
		{
			name:        "named profile with write access",
			profileName: "high-access",
			permissions: []string{"contents:write", "pull_requests:write", "metadata:read"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
				return "https://github.com/org/repo-url.git", nil
			})

			var capturedPermissions []string
			tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, permissions []string) (string, time.Time, error) {
				capturedPermissions = permissions
				return "vended-token-value", vendedDate, nil
			})

			v := vendor.Vending(vendor.PipelineRepositories(repoLookup), tokenVendor)

			ref := profile.ProfileRef{
				Organization: "organization-slug",
				Name:         tc.profileName,
				Type:         profile.ProfileTypeRepo,
				PipelineID:   "pipeline-id",
				PipelineSlug: "my-pipeline",
			}
			resolved := pipelineResolved(ref, profile.PipelineProfileAttr{Permissions: tc.permissions})

			result := v(createTestClaimsContextWithPipeline("my-pipeline"), resolved, "")

			assertVendorSuccess(t, result, vendor.ProfileToken{
				Token:               "vended-token-value",
				HashedToken:         vendor.HashToken("vended-token-value"),
				Repositories:        profile.NewSpecificScope("repo-url"),
				Permissions:         tc.permissions,
				Profile:             "repo:" + tc.profileName,
				Expiry:              vendedDate,
				OrganizationSlug:    "organization-slug",
				VendedRepositoryURL: "https://github.com/org/repo-url.git",
			})
			assert.Equal(t, tc.permissions, capturedPermissions, "the token must be minted with the resolved profile's permissions")
		})
	}
}
