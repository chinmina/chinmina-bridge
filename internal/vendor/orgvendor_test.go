package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/github/githubtest"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	v := vendor.NewOrgVendor(githubtest.CreateTestProfileStore(), nil)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo, // Wrong type!
		PipelineID:   "pipeline-id",
	}
	_, err := v(context.Background(), ref, "repo-url")
	require.ErrorContains(t, err, "profile type mismatch")
	require.ErrorContains(t, err, "org")
	require.ErrorContains(t, err, "repo")
}

func TestOrgVendor_FailWhenProfileNotFound(t *testing.T) {
	v := vendor.NewOrgVendor(githubtest.CreateTestProfileStore(), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-existent-profile",
		Type:         profile.ProfileTypeOrg,
	}
	_, err := v(context.Background(), ref, "repo-url")
	require.ErrorContains(t, err, "could not find profile")
}

func TestOrgVendor_FailWhenURLInvalid(t *testing.T) {
	v := vendor.NewOrgVendor(githubtest.CreateTestProfileStore(), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}
	tok, err := v(createTestClaimsContext(), ref, ":/invalid_")

	require.ErrorContains(t, err, "could not parse requested repo URL")
	require.Nil(t, tok)
}

func TestOrgVendor_SuccessfulNilOnRepoMismatch(t *testing.T) {
	v := vendor.NewOrgVendor(githubtest.CreateTestProfileStore(), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}
	tok, err := v(createTestClaimsContext(), ref, "https://github.com/org/i-dont-exist")

	assert.NoError(t, err)
	assert.Nil(t, tok)
}

func TestOrgVendor_FailWhenTokenVendorFails(t *testing.T) {
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("token vendor failed")
	})

	v := vendor.NewOrgVendor(githubtest.CreateTestProfileStore(), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}
	tok, err := v(createTestClaimsContext(), ref, "https://github.com/org/secret-repo")

	assert.ErrorContains(t, err, "token vendor failed")
	assert.Nil(t, tok)
}

func TestOrgVendor_SuccessfulTokenProvisioning(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "non-default-token-value", vendedDate, nil
	})
	v := vendor.NewOrgVendor(githubtest.CreateTestProfileStore(), tokenVendor)

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
			tok, err := v(createTestClaimsContext(), ref, tt.requestedURL)
			assert.NoError(t, err)
			assert.Equal(t, &vendor.ProfileToken{
				Token:                  "non-default-token-value",
				Repositories:           []string{"secret-repo", "another-secret-repo"},
				Permissions:            []string{"contents:read", "packages:read"},
				Profile:                "org:non-default-profile",
				Expiry:                 vendedDate,
				OrganizationSlug:       "organization-slug",
				RequestedRepositoryURL: tt.requestedURL,
			}, tok)
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
	createMatchingProfileStore := func() *github.ProfileStore {
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
		profileConfig, err := github.ValidateProfile(context.Background(), profileYAML)
		if err != nil {
			t.Fatalf("failed to validate profile: %v", err)
		}

		store := github.NewProfileStore()
		store.Update(&profileConfig)
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

		tok, err := v(ctx, ref, "")
		require.NoError(t, err)
		require.NotNil(t, tok)
		assert.Equal(t, "test-token", tok.Token)
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

		tok, err := v(ctx, ref, "")
		require.Error(t, err)
		assert.Nil(t, tok)

		var matchErr github.ProfileMatchFailedError
		require.ErrorAs(t, err, &matchErr)
		assert.Equal(t, "prod-deploy", matchErr.Name)
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

		tok, err := v(ctx, ref, "")
		require.NoError(t, err)
		require.NotNil(t, tok)
		assert.Equal(t, "test-token", tok.Token)
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

		tok, err := v(ctx, ref, "")
		require.Error(t, err)
		assert.Nil(t, tok)

		var matchErr github.ProfileMatchFailedError
		require.ErrorAs(t, err, &matchErr)
		assert.Equal(t, "staging-deploy", matchErr.Name)
	})
}
