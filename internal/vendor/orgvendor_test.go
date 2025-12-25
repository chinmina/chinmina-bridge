package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/profile/profiletest"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
)

// createTestClaimsContext creates a context with test Buildkite claims for tests.
// Used for tests that get past profile lookup and need claims for match evaluation.
func createTestClaimsContext() context.Context {
	claims := &jwt.BuildkiteClaims{
		OrganizationSlug: "organization-slug",
		PipelineSlug:     "test-pipeline",
		PipelineID:       "pipeline-123",
		BuildNumber:      1,
	}

	return jwt.ContextWithBuildkiteClaims(context.Background(), claims)
}

func TestOrgVendor_FailsWithWrongProfileType(t *testing.T) {
	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(), nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo, // Wrong type!
		PipelineID:   "pipeline-id",
	}
	result := v(context.Background(), ref, "repo-url")
	assertVendorFailure(t, result, "profile type mismatch")
}

func TestOrgVendor_FailWhenProfileNotFound(t *testing.T) {
	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-existent-profile",
		Type:         profile.ProfileTypeOrg,
	}
	result := v(context.Background(), ref, "repo-url")
	assertVendorFailure(t, result, "could not find profile")
}

func TestOrgVendor_FailWhenURLInvalid(t *testing.T) {
	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}
	result := v(createTestClaimsContext(), ref, ":/invalid_")

	assertVendorFailure(t, result, "could not parse requested repo URL")
}

func TestOrgVendor_SuccessfulNilOnRepoMismatch(t *testing.T) {
	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}
	result := v(createTestClaimsContext(), ref, "https://github.com/org/i-dont-exist")

	assertVendorUnmatched(t, result)
}

func TestOrgVendor_FailWhenTokenVendorFails(t *testing.T) {
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("token vendor failed")
	})

	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}
	result := v(createTestClaimsContext(), ref, "https://github.com/org/secret-repo")

	assertVendorFailure(t, result, "token vendor failed")
}

func TestOrgVendor_SuccessfulTokenProvisioning(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "non-default-token-value", vendedDate, nil
	})
	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(), tokenVendor)

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
			result := v(createTestClaimsContext(), ref, tt.requestedURL)
			assertVendorSuccess(t, result, vendor.ProfileToken{
				Token:               "non-default-token-value",
				Repositories:        []string{"secret-repo", "another-secret-repo"},
				Permissions:         []string{"contents:read", "packages:read"},
				Profile:             "org:non-default-profile",
				Expiry:              vendedDate,
				OrganizationSlug:    "organization-slug",
				VendedRepositoryURL: tt.requestedURL,
			})
		})
	}
}

func TestOrgVendor_MatchEvaluation(t *testing.T) {
	// Helper to create validated claims with BuildkiteClaims
	createClaimsContext := func(pipelineSlug string, buildBranch string) context.Context {
		claims := &jwt.BuildkiteClaims{
			OrganizationSlug: "test-org",
			PipelineSlug:     pipelineSlug,
			PipelineID:       "pipeline-123",
			BuildNumber:      42,
			BuildBranch:      buildBranch,
		}

		return jwt.ContextWithBuildkiteClaims(context.Background(), claims)
	}

	// Create profile store with match rules
	createMatchingProfileStore := func() *profile.ProfileStore {
		// Load profile YAML with match rules to get compiled matchers
		profileYAML := `
organization:
  profiles:
    - name: prod-deploy
      match:
        - claim: pipeline_slug
          value: silk-prod
      repositories: [test-repo]
      permissions: [contents:write]
    - name: staging-deploy
      match:
        - claim: pipeline_slug
          valuePattern: ".*-staging"
        - claim: build_branch
          value: main
      repositories: [test-repo]
      permissions: [contents:read]
`
		profileConfig, err := profile.ValidateProfile(context.Background(), profileYAML)
		if err != nil {
			t.Fatalf("failed to validate profile: %v", err)
		}

		store := profile.NewProfileStore()
		store.Update(profileConfig)
		return store
	}

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "test-token", time.Now(), nil
	})

	t.Run("match success with exact value", func(t *testing.T) {
		store := createMatchingProfileStore()
		v := vendor.NewOrgVendor(store, tokenVendor)

		ctx := createClaimsContext("silk-prod", "main")
		ref := profile.ProfileRef{
			Organization: "test-org",
			Name:         "prod-deploy",
			Type:         profile.ProfileTypeOrg,
		}

		result := v(ctx, ref, "")
		assertVendorTokenValue(t, result, "test-token")
	})

	t.Run("match failure with wrong value", func(t *testing.T) {
		store := createMatchingProfileStore()
		v := vendor.NewOrgVendor(store, tokenVendor)

		ctx := createClaimsContext("silk-staging", "main")
		ref := profile.ProfileRef{
			Organization: "test-org",
			Name:         "prod-deploy",
			Type:         profile.ProfileTypeOrg,
		}

		result := v(ctx, ref, "")
		assertVendorFailure(t, result, "prod-deploy")
	})

	t.Run("match success with multiple rules", func(t *testing.T) {
		store := createMatchingProfileStore()
		v := vendor.NewOrgVendor(store, tokenVendor)

		ctx := createClaimsContext("silk-staging", "main")
		ref := profile.ProfileRef{
			Organization: "test-org",
			Name:         "staging-deploy",
			Type:         profile.ProfileTypeOrg,
		}

		result := v(ctx, ref, "")
		assertVendorTokenValue(t, result, "test-token")
	})

	t.Run("match failure with multiple rules - one fails", func(t *testing.T) {
		store := createMatchingProfileStore()
		v := vendor.NewOrgVendor(store, tokenVendor)

		ctx := createClaimsContext("silk-staging", "feature")
		ref := profile.ProfileRef{
			Organization: "test-org",
			Name:         "staging-deploy",
			Type:         profile.ProfileTypeOrg,
		}

		result := v(ctx, ref, "")
		assertVendorFailure(t, result, "staging-deploy")
	})
}
