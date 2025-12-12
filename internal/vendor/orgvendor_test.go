package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/github/githubtest"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	tok, err := v(context.Background(), ref, ":/invalid_")

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
	tok, err := v(context.Background(), ref, "https://github.com/org/i-dont-exist")

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
	tok, err := v(context.Background(), ref, "https://github.com/org/secret-repo")

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
			tok, err := v(context.Background(), ref, tt.requestedURL)
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
