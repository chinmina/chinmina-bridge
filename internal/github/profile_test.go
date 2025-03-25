package github_test

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	api "github.com/google/go-github/v61/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed profile/valid_profile.yaml
var profile string

//go:embed profile/invalid_profile.yaml
var invalidProfile string

// Test that the URL Decomposition logic works as expected
func TestURLDecomposition(t *testing.T) {
	// Example of a valid profile URL
	configURL, _ := url.Parse("https://github.com/chinmina/chinmina-bridge/docs/profile.yaml")
	// Test that the profile URL is valid

	owner, repo, path := github.DecomposePath(*configURL)
	assert.Equal(t, "chinmina", owner)
	assert.Equal(t, "chinmina-bridge", repo)
	assert.Equal(t, "docs/profile.yaml", path)

	// Example of an invalid profile URL
	configURL, _ = url.Parse("https://github.com/chinmina/non-existent-profile.yaml")

	// Test that the profile URL is invalid (path contains missing owner/repo)
	owner, repo, path = github.DecomposePath(*configURL)
	assert.Equal(t, "", owner)
	assert.Equal(t, "", repo)
	assert.Equal(t, "", path)
}

// Test that repository contents are handled correctly
func TestRepositoryContents(t *testing.T) {
	router := http.NewServeMux()
	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.InstallationToken{
			Token:     api.String("expected-token"),
			ExpiresAt: &api.Timestamp{Time: expectedExpiry},
		})
	})

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/profile.yaml", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.RepositoryContent{
			Content: &profile,
		})
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	// Example of a valid profile URL
	configURL, _ := url.Parse("github.com/chinmina/chinmina-bridge/docs/profile.yaml")
	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	// Load the profile
	profile, err = github.GetProfile(context.Background(), gh, *configURL)
	require.NoError(t, err)
}

func TestInvalidRepositoryContents(t *testing.T) {
	router := http.NewServeMux()
	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.InstallationToken{
			Token:     api.String("expected-token"),
			ExpiresAt: &api.Timestamp{Time: expectedExpiry},
		})
	})

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/profile.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	// Example of an invalid profile URL
	configURL, err := url.Parse("github.com/chinmina/chinmina-bridge/docs/profile.yaml")
	if err != nil {
		fmt.Errorf("url conversion from string format failed: %w", err)
	}
	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	// Load the profile
	_, err = github.GetProfile(context.Background(), gh, *configURL)
	require.Error(t, err)
	assert.ErrorContains(t, err, ": 418")
}

// Test that the profile that is loaded is valid
func TestValidProfile(t *testing.T) {
	_, err := github.ValidateProfile(context.Background(), profile)

	require.NoError(t, err)
}

// Test case where the profile that is loaded is invalid
func TestInvalidProfile(t *testing.T) {
	_, err := github.ValidateProfile(context.Background(), invalidProfile)

	require.Error(t, err)
}

func TestLoadProfile(t *testing.T) {
	router := http.NewServeMux()

	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.InstallationToken{
			Token:     api.String("expected-token"),
			ExpiresAt: &api.Timestamp{Time: expectedExpiry},
		})
	})

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/profile.yaml", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.RepositoryContent{
			Content: &profile,
		})
	})

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/invalid-profile.yaml", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.RepositoryContent{
			Content: &invalidProfile,
		})
	})

	router.HandleFunc("/repos/chinmina/non-existent-profile.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	// Example of a valid profile URL
	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	validProfile, _ := github.ValidateProfile(context.Background(), profile)

	testCases := []struct {
		configURL      string
		expectedConfig github.ProfileConfig
		errorAssertion assert.ErrorAssertionFunc
	}{
		{
			configURL:      "github.com/chinmina/chinmina-bridge/docs/profile.yaml",
			expectedConfig: validProfile,
			errorAssertion: assert.NoError,
		},
		{
			configURL:      "github.com/chinmina/non-existent-profile.yaml",
			expectedConfig: github.ProfileConfig{},
			errorAssertion: assert.Error,
		},
		{
			configURL:      "github.com/chinmina/chinmina-bridge/docs/invalid-profile.yaml",
			expectedConfig: github.ProfileConfig{},
			errorAssertion: assert.Error,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.configURL, func(t *testing.T) {
			updatedURL, err := url.Parse(tc.configURL)
			result, err := github.LoadProfile(context.Background(), gh, *updatedURL)
			tc.errorAssertion(t, err)
			assert.Equal(t, tc.expectedConfig, result)
		})
	}
}

func TestFetchProfile(t *testing.T) {
	router := http.NewServeMux()
	profileStore := github.NewProfileStore()

	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.InstallationToken{
			Token:     api.String("expected-token"),
			ExpiresAt: &api.Timestamp{Time: expectedExpiry},
		})
	})

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/profile.yaml", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.RepositoryContent{
			Content: &profile,
		})
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	// Example of a valid profile URL
	configURL, err := url.Parse("github.com/chinmina/chinmina-bridge/docs/profile.yaml")
	if err != nil {
		fmt.Errorf("url conversion from string format failed: %w", err)
	}
	fakeURL, err := url.Parse("github.com/chinmina/chinmina-bridge/docs/fake-profile.yaml")
	if err != nil {
		fmt.Errorf("url conversion from string format failed: %w", err)
	}
	gh, err := github.New(
		context.Background(),
		config.GithubConfig{
			ApiURL:         svr.URL,
			PrivateKey:     key,
			ApplicationID:  10,
			InstallationID: 20,
		},
	)
	require.NoError(t, err)

	validatedProfile, err := github.ValidateProfile(context.Background(), profile)
	require.NoError(t, err)

	// Test that we get an error attempting to load it before fetching
	_, err = profileStore.GetOrganization()
	require.Error(t, err)

	orgProfile, err := github.FetchOrganizationProfile(context.Background(), *configURL, gh)
	require.NoError(t, err)
	assert.Equal(t, validatedProfile, orgProfile)

	orgProfile, err = github.FetchOrganizationProfile(context.Background(), *configURL, gh)
	require.NoError(t, err)

	profileStore.Update(&orgProfile)
	loadedProfile, err := profileStore.GetOrganization()
	require.NoError(t, err)
	assert.Equal(t, loadedProfile, validatedProfile)

	_, err = github.FetchOrganizationProfile(context.Background(), *fakeURL, gh)
	require.Error(t, err)
}

// Test the case where the profile is inconsistent with the request made to Chinmina
// In this case, the target repository is not included in the targeted profile
func TestProfile(t *testing.T) {
	testCases := []struct {
		profileName           string
		repositoryName        string
		expectedHasProfile    bool
		expectedHasRepository bool
	}{
		{
			profileName:           "buildkite-plugin",
			repositoryName:        "fake-repo",
			expectedHasProfile:    true,
			expectedHasRepository: false,
		},
		{
			profileName:           "fake-profile",
			repositoryName:        "fake-repo",
			expectedHasProfile:    false,
			expectedHasRepository: false,
		},
		{
			profileName:           "buildkite-plugin",
			repositoryName:        "very-private-buildkite-plugin",
			expectedHasProfile:    true,
			expectedHasRepository: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.profileName, func(t *testing.T) {
			profileConfig, err := github.ValidateProfile(context.Background(), profile)
			require.NoError(t, err)

			_, ok := profileConfig.LookupProfile(tc.profileName)
			assert.Equal(t, ok, tc.expectedHasProfile)
			assert.Equal(t, profileConfig.HasRepository(tc.profileName, tc.repositoryName), tc.expectedHasRepository)
		})
	}
}
