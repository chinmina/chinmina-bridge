package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var store = testhelpers.CreateTestProfileStore()

func TestVendor_FailWhenProfileMalformed(t *testing.T) {

	v := vendor.New(nil, nil, store)

	_, err := v(context.Background(), jwt.BuildkiteClaims{}, "repo-url", "default")
	require.ErrorContains(t, err, "profile is not colon-separated")
}

func TestVendor_DefaultProfile_FailWhenPipelineLookupFails(t *testing.T) {

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "", errors.New("pipeline not found")
	})

	v := vendor.New(repoLookup, nil, store)

	_, err := v(context.Background(), jwt.BuildkiteClaims{}, "repo-url", "repo:default")
	require.ErrorContains(t, err, "could not find repository for pipeline")
}

func TestVendor_DefaultProfile_SuccessfulNilOnRepoMismatch(t *testing.T) {

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "repo-url-mismatch", nil
	})
	v := vendor.New(repoLookup, nil, store)

	// when there is a difference between the requested pipeline (by Git
	// generally) and the repo associated with the pipeline, return success but
	// empty. This indicates that there are not credentials that can be issued.

	tok, err := v(
		context.Background(),
		jwt.BuildkiteClaims{PipelineID: "pipeline-id", PipelineSlug: "pipeline-slug", OrganizationSlug: "organization-slug"},
		"repo-url",
		"repo:default",
	)
	assert.NoError(t, err)
	assert.Nil(t, tok)
}

func TestVendor_DefaultProfile_FailsWhenTokenVendorFails(t *testing.T) {

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("token vendor failed")
	})
	v := vendor.New(repoLookup, tokenVendor, store)

	tok, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id", PipelineSlug: "pipeline-slug", OrganizationSlug: "organization-slug"}, "https://github.com/org/repo-url", "repo:default")
	assert.ErrorContains(t, err, "token vendor failed")
	assert.Nil(t, tok)
}

func TestVendor_DefaultProfile_SucceedsWithTokenWhenPossible(t *testing.T) {

	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	repoLookup := vendor.RepositoryLookup(func(ctx context.Context, org string, pipeline string) (string, error) {
		return "https://github.com/org/repo-url", nil
	})
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "vended-token-value", vendedDate, nil
	})
	v := vendor.New(repoLookup, tokenVendor, store)

	tok, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id", PipelineSlug: "pipeline-slug", OrganizationSlug: "organization-slug"}, "https://github.com/org/repo-url", "repo:default")
	assert.NoError(t, err)
	assert.Equal(t, tok, &vendor.ProfileToken{
		Token:                  "vended-token-value",
		Repositories:           []string{"repo-url"},
		Permissions:            []string{"contents:read"},
		Profile:                "repo:default",
		Expiry:                 vendedDate,
		OrganizationSlug:       "organization-slug",
		RequestedRepositoryURL: "https://github.com/org/repo-url",
	})
}

func TestVendor_NonDefaultProfile_FailWhenProfileLookupFails(t *testing.T) {

	v := vendor.New(nil, nil, store)

	_, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id", PipelineSlug: "pipeline-slug", OrganizationSlug: "organization-slug"}, "repo-url", "org:non-existant-profile")
	require.ErrorContains(t, err, "could not find profile")
}

func TestVendor_NonDefaultProfile_FailWhenURLInvalid(t *testing.T) {

	v := vendor.New(nil, nil, store)

	tok, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id", PipelineSlug: "pipeline-slug", OrganizationSlug: "organization-slug"}, ":/invalid_", "org:non-default-profile")

	assert.ErrorContains(t, err, "could not parse requested repo URL")
	assert.Nil(t, tok)
}

func TestVendor_NonDefaultProfile_SuccessfulNilOnRepoMismatch(t *testing.T) {

	v := vendor.New(nil, nil, store)

	tok, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id", PipelineSlug: "pipeline-slug", OrganizationSlug: "organization-slug"}, "https://github.com/org/i-dont-exist", "org:non-default-profile")

	assert.NoError(t, err)
	assert.Nil(t, tok)
}

func TestVendor_NonDefaultProfile_FailWhenTokenVendorFails(t *testing.T) {

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("token vendor failed")
	})

	v := vendor.New(nil, tokenVendor, store)

	tok, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id", PipelineSlug: "pipeline-slug", OrganizationSlug: "organization-slug"}, "https://github.com/org/secret-repo", "org:non-default-profile")

	assert.ErrorContains(t, err, "token vendor failed")
	assert.Nil(t, tok)
}

func TestVendor_NonDefaultProfile_SucceedsWithTokenWhenPossible(t *testing.T) {

	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "non-default-token-value", vendedDate, nil
	})
	v := vendor.New(nil, tokenVendor, store)

	tok, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id", PipelineSlug: "pipeline-slug", OrganizationSlug: "organization-slug"}, "https://github.com/org/secret-repo", "org:non-default-profile")
	assert.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "non-default-token-value",
		Repositories:           []string{"secret-repo", "another-secret-repo"},
		Permissions:            []string{"contents:read", "packages:read"},
		Profile:                "org:non-default-profile",
		Expiry:                 vendedDate,
		OrganizationSlug:       "organization-slug",
		RequestedRepositoryURL: "https://github.com/org/secret-repo",
	}, tok)
}

func TestPipelineRepositoryToken_URL(t *testing.T) {
	testCases := []struct {
		name          string
		repositoryURL string
		expectedURL   string
		expectedError string
	}{
		{
			name:          "valid absolute URL",
			repositoryURL: "https://github.com/org/repo",
			expectedURL:   "https://github.com/org/repo",
		},
		{
			name:          "valid absolute URL with path",
			repositoryURL: "https://github.com/org/repo/path/to/file",
			expectedURL:   "https://github.com/org/repo/path/to/file",
		},
		{
			name:          "invalid relative URL",
			repositoryURL: "org/repo",
			expectedError: "repository URL must be absolute: org/repo",
		},
		{
			name:          "invalid URL",
			repositoryURL: "://invalid",
			expectedError: "parse \"://invalid\": missing protocol scheme",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := vendor.ProfileToken{RequestedRepositoryURL: tc.repositoryURL}
			url, err := token.URL()

			if tc.expectedError != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedURL, url.String())
			}
		})
	}
}

func TestVendor_NonDefaultProfile_SucceedsWithEmptyRequestedRepo(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repositoryURLs []string, scopes []string) (string, time.Time, error) {
		return "non-default-token-value", vendedDate, nil
	})
	v := vendor.New(nil, tokenVendor, store)

	tok, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id", PipelineSlug: "pipeline-slug", OrganizationSlug: "organization-slug"}, "", "org:non-default-profile")
	assert.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "non-default-token-value",
		Repositories:           []string{"secret-repo", "another-secret-repo"},
		Permissions:            []string{"contents:read", "packages:read"},
		Profile:                "org:non-default-profile",
		Expiry:                 vendedDate,
		OrganizationSlug:       "organization-slug",
		RequestedRepositoryURL: "",
	}, tok)
}

func TestPipelineRepositoryToken_ExpiryUnix(t *testing.T) {
	testCases := []struct {
		name     string
		expiry   time.Time
		expected string
	}{
		{
			name:     "UTC time",
			expiry:   time.Date(2023, 5, 1, 12, 0, 0, 0, time.UTC),
			expected: "1682942400",
		},
		{
			name:     "+1000 timezone",
			expiry:   time.Date(2023, 5, 1, 22, 0, 0, 0, time.FixedZone("+1000", 10*60*60)),
			expected: "1682942400",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := vendor.ProfileToken{
				Expiry: tc.expiry,
			}

			actual := token.ExpiryUnix()
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestTransformSSHToHTTPS(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "ssh, valid GitHub",
			url:      "git@github.com:organization/chinmina.git",
			expected: "https://github.com/organization/chinmina.git",
		},
		{
			name:     "ssh, no user",
			url:      "github.com:organization/chinmina.git",
			expected: "github.com:organization/chinmina.git",
		},
		{
			name:     "ssh, different host",
			url:      "git@githab.com:organization/chinmina.git",
			expected: "git@githab.com:organization/chinmina.git",
		},
		{
			name:     "ssh, another different host",
			url:      "git@githubxcom:organization/chinmina.git",
			expected: "git@githubxcom:organization/chinmina.git",
		},
		{
			name:     "ssh, invalid path specifier",
			url:      "git@github.com/organization/chinmina.git",
			expected: "git@github.com/organization/chinmina.git",
		},
		{
			name:     "ssh, zero length path",
			url:      "git@github.com:",
			expected: "git@github.com:",
		},
		{
			name:     "ssh, no extension",
			url:      "git@github.com:organization/chinmina",
			expected: "https://github.com/organization/chinmina",
		},
		{
			name:     "https, valid",
			url:      "https://github.com/organization/chinmina.git",
			expected: "https://github.com/organization/chinmina.git",
		},
		{
			name:     "https, nonsense",
			url:      "https://githubxcom/passthrough.git",
			expected: "https://githubxcom/passthrough.git",
		},
		{
			name:     "http, valid",
			url:      "http://github.com/organization/chinmina.git",
			expected: "http://github.com/organization/chinmina.git",
		},
		{
			name:     "pure nonsense",
			url:      "molybdenum://mo",
			expected: "molybdenum://mo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := vendor.TranslateSSHToHTTPS(tc.url)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
