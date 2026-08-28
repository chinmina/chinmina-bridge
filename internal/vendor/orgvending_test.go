package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
)

// createTestClaimsContext creates a context with test Buildkite claims for tests.
// Used for tests that carry claims through vending, mirroring a request that
// was authorized at the handler boundary.
func createTestClaimsContext() context.Context {
	claims := &jwt.BuildkiteClaims{
		OrganizationSlug: "organization-slug",
		PipelineSlug:     "test-pipeline",
		PipelineID:       "pipeline-123",
		BuildNumber:      1,
	}

	return jwt.ContextWithBuildkiteClaims(context.Background(), claims)
}

func TestOrgVending_FailWhenURLInvalid(t *testing.T) {
	v := vendor.Vending(vendor.OrgRepositories, nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewSpecificScope("secret-repo", "another-secret-repo"),
		Permissions: []string{"contents:read", "packages:read", "metadata:read"},
	}
	result := v(createTestClaimsContext(), orgResolved(ref, attrs), ":/invalid_")

	assertVendorFailure(t, result, "could not parse requested repo URL")
}

func TestOrgVending_SuccessfulNilOnRepoMismatch(t *testing.T) {
	v := vendor.Vending(vendor.OrgRepositories, nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewSpecificScope("secret-repo", "another-secret-repo"),
		Permissions: []string{"contents:read", "packages:read", "metadata:read"},
	}
	result := v(createTestClaimsContext(), orgResolved(ref, attrs), "https://github.com/org/i-dont-exist")

	assertVendorUnmatched(t, result)
}

func TestOrgVending_FailWhenTokenVendorFails(t *testing.T) {
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("token vendor failed")
	})

	v := vendor.Vending(vendor.OrgRepositories, mintingThrough(tokenVendor))

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewSpecificScope("secret-repo", "another-secret-repo"),
		Permissions: []string{"contents:read", "packages:read", "metadata:read"},
	}
	result := v(createTestClaimsContext(), orgResolved(ref, attrs), "https://github.com/org/secret-repo")

	assertVendorFailure(t, result, "token vendor failed")
}

func TestOrgVending_SuccessfulTokenProvisioning(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "non-default-token-value", vendedDate, nil
	})
	v := vendor.Vending(vendor.OrgRepositories, mintingThrough(tokenVendor))

	tests := []struct {
		name         string
		requestedURL string
	}{
		{
			name:         "WithSpecificRepositoryURL",
			requestedURL: "https://github.com/org/secret-repo",
		},
		{
			name:         "WithEmptyRepositoryURL",
			requestedURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := profile.ProfileRef{
				Organization: "organization-slug",
				Name:         "non-default-profile",
				Type:         profile.ProfileTypeOrg,
			}
			attrs := profile.OrganizationProfileAttr{
				Scope:       profile.NewSpecificScope("secret-repo", "another-secret-repo"),
				Permissions: []string{"contents:read", "packages:read", "metadata:read"},
			}
			result := v(createTestClaimsContext(), orgResolved(ref, attrs), tt.requestedURL)
			assertVendorSuccess(t, result, vendor.ProfileToken{
				Token:               "non-default-token-value",
				HashedToken:         vendor.HashToken("non-default-token-value"),
				App:                 "publisher",
				ApplicationID:       4242,
				InstallationID:      8484,
				Repositories:        profile.NewSpecificScope("secret-repo", "another-secret-repo"),
				Permissions:         []string{"contents:read", "packages:read", "metadata:read"},
				Profile:             "org:non-default-profile",
				Expiry:              vendedDate,
				OrganizationSlug:    "organization-slug",
				VendedRepositoryURL: tt.requestedURL,
			})
		})
	}
}

func TestOrgVending_WildcardRepository(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	// Token vendor that verifies nil is passed for repositories
	var capturedRepositories []string
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		capturedRepositories = repositoryURLs
		return "wildcard-token-value", vendedDate, nil
	})

	v := vendor.Vending(vendor.OrgRepositories, mintingThrough(tokenVendor))

	tests := []struct {
		name         string
		requestedURL string
	}{
		{
			name:         "WithSpecificRepositoryURL",
			requestedURL: "https://github.com/org/any-repo",
		},
		{
			name:         "WithEmptyRepositoryURL",
			requestedURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capturedRepositories = []string{"sentinel"}

			ref := profile.ProfileRef{
				Organization: "organization-slug",
				Name:         "wildcard-profile",
				Type:         profile.ProfileTypeOrg,
			}
			attrs := profile.OrganizationProfileAttr{
				Scope:       profile.NewWildcardScope(),
				Permissions: []string{"contents:read", "packages:read", "metadata:read"},
			}
			result := v(createTestClaimsContext(), orgResolved(ref, attrs), tt.requestedURL)

			// Verify nil was passed to token vendor (indicates all repositories)
			assert.Nil(t, capturedRepositories)

			assertVendorSuccess(t, result, vendor.ProfileToken{
				Token:               "wildcard-token-value",
				HashedToken:         vendor.HashToken("wildcard-token-value"),
				App:                 "publisher",
				ApplicationID:       4242,
				InstallationID:      8484,
				Repositories:        profile.NewWildcardScope(),
				Permissions:         []string{"contents:read", "packages:read", "metadata:read"},
				Profile:             "org:wildcard-profile",
				Expiry:              vendedDate,
				OrganizationSlug:    "organization-slug",
				VendedRepositoryURL: tt.requestedURL,
			})
		})
	}
}

func TestOrgVending_CallerScopedRepository_Success(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	var capturedRepoNames []string
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		capturedRepoNames = repoNames
		return "scoped-token", vendedDate, nil
	})

	v := vendor.Vending(vendor.OrgRepositories, mintingThrough(tokenVendor))

	ref := profile.ProfileRef{
		Organization:     "organization-slug",
		Name:             "caller-scoped-profile",
		Type:             profile.ProfileTypeOrg,
		ScopedRepository: "target-repo",
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewCallerScopedScope(),
		Permissions: []string{"contents:write", "metadata:read"},
	}

	ctx := createTestClaimsContextWithPipeline("agent-workflows")
	result := v(ctx, orgResolved(ref, attrs), "")

	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "scoped-token",
		HashedToken:         vendor.HashToken("scoped-token"),
		App:                 "publisher",
		ApplicationID:       4242,
		InstallationID:      8484,
		Repositories:        profile.NewSpecificScope("target-repo"),
		Permissions:         []string{"contents:write", "metadata:read"},
		Profile:             "org:caller-scoped-profile/target-repo",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "",
	})
	assert.Equal(t, []string{"target-repo"}, capturedRepoNames)
}

func TestOrgVending_CallerScoped_MissingScopeParameter(t *testing.T) {
	// Defence-in-depth (resolveRequestScope guard): the resolver normally
	// guarantees a non-empty ScopedRepository for caller-scoped profiles, but the
	// vendor is exported. If a caller-scoped ref reaches the vendor with an empty
	// ScopedRepository, the vendor must fail rather than vend a token for the
	// repository name "".
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		t.Errorf("token vendor must not be called for an empty caller scope; got repoNames=%v", repoNames)
		return "", time.Time{}, nil
	})

	v := vendor.Vending(vendor.OrgRepositories, mintingThrough(tokenVendor))

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "caller-scoped-profile",
		Type:         profile.ProfileTypeOrg,
		// ScopedRepository intentionally empty.
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewCallerScopedScope(),
		Permissions: []string{"contents:write", "metadata:read"},
	}

	ctx := createTestClaimsContextWithPipeline("agent-workflows")
	result := v(ctx, orgResolved(ref, attrs), "")

	assertVendorFailure(t, result, "requires a non-empty repository scope")
}

// Scope supplied to a profile that does not accept one is rejected at the
// handler boundary, never here: see TestProfileResolver_OrgStaticList_RejectsScope
// and TestHandlePostToken_OrgStaticList_RejectsScopeWithSpecificMessage in the
// root package.

func TestOrgVending_GitCredentials_CallerScoped_DerivesRepoFromURL(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	var capturedRepoNames []string
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		capturedRepoNames = repoNames
		return "scoped-token", vendedDate, nil
	})

	v := vendor.Vending(vendor.OrgRepositories, mintingThrough(tokenVendor))

	ref := profile.ProfileRef{
		Organization:     "organization-slug",
		Name:             "caller-scoped-profile",
		Type:             profile.ProfileTypeOrg,
		ScopedRepository: "target-repo", // Derived from the URL by the handler
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewCallerScopedScope(),
		Permissions: []string{"contents:write", "metadata:read"},
	}

	// Git-credentials passes requestedRepoURL for repo matching, not scope resolution
	ctx := createTestClaimsContextWithPipeline("agent-workflows")
	result := v(ctx, orgResolved(ref, attrs), "https://github.com/org/target-repo")

	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "scoped-token",
		HashedToken:         vendor.HashToken("scoped-token"),
		App:                 "publisher",
		ApplicationID:       4242,
		InstallationID:      8484,
		Repositories:        profile.NewSpecificScope("target-repo"),
		Permissions:         []string{"contents:write", "metadata:read"},
		Profile:             "org:caller-scoped-profile/target-repo",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "https://github.com/org/target-repo",
	})
	assert.Equal(t, []string{"target-repo"}, capturedRepoNames)
}

func TestOrgVending_GitCredentials_CallerScoped_IssuanceFailure(t *testing.T) {
	// Req 3.1/7.1: for a caller-scoped profile, a token-issuance failure must be
	// a vendor failure (→ 403 at the handler), never an unmatched/empty-success.
	// Mirrors TestOrgVending_GitCredentials_AllRepos_NoUnmatched for the
	// caller-scoped path.
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("GitHub API rejected request")
	})

	v := vendor.Vending(vendor.OrgRepositories, mintingThrough(tokenVendor))

	ref := profile.ProfileRef{
		Organization:     "organization-slug",
		Name:             "caller-scoped-profile",
		Type:             profile.ProfileTypeOrg,
		ScopedRepository: "target-repo",
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewCallerScopedScope(),
		Permissions: []string{"contents:write", "metadata:read"},
	}

	ctx := createTestClaimsContextWithPipeline("agent-workflows")
	result := v(ctx, orgResolved(ref, attrs), "https://github.com/org/target-repo")

	// Must be a failure, not an unmatched (empty-success).
	assertVendorFailure(t, result, "GitHub API rejected request")
}

func TestOrgVending_GitCredentials_AllRepos_NoUnmatched(t *testing.T) {
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("GitHub API rejected request")
	})

	v := vendor.Vending(vendor.OrgRepositories, mintingThrough(tokenVendor))

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "all-repos-profile",
		Type:         profile.ProfileTypeOrg,
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewWildcardScope(),
		Permissions: []string{"contents:read", "metadata:read"},
	}

	ctx := createTestClaimsContext()
	result := v(ctx, orgResolved(ref, attrs), "https://github.com/org/any-repo")

	// Must be a failure, not an unmatched (empty-success)
	assertVendorFailure(t, result, "GitHub API rejected request")
}
