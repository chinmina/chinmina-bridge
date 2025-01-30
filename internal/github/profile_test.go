package github_test

import (
	"context"
	_ "embed"
	"net/http"
	"net/http/httptest"
	"testing"

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
	configURL := "github.com/chinmina/chinmina-bridge/docs/profile.yaml"

	// Test that the profile URL is valid
	owner, repo, path := github.DecomposePath(configURL)
	assert.Equal(t, "chinmina", owner)
	assert.Equal(t, "chinmina-bridge", repo)
	assert.Equal(t, "docs/profile.yaml", path)

	// Example of an invalid profile URL
	configURL = "github.com/chinmina/non-existent-profile.yaml"
	// Test that the profile URL is valid
	owner, repo, path = github.DecomposePath(configURL)
	assert.Equal(t, "", owner)
	assert.Equal(t, "", repo)
	assert.Equal(t, "", path)

}

// Test that repository contents are handled correctly
func TestRepositoryContents(t *testing.T) {

	router := http.NewServeMux()

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
	configURL := "github.com/chinmina/chinmina-bridge/docs/profile.yaml"
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
	profile, err = github.GetProfile(context.Background(), gh, configURL)
	require.NoError(t, err)
}

func TestInvalidRepositoryContents(t *testing.T) {

	router := http.NewServeMux()

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/profile.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	// generate valid key for testing
	key := generateKey(t)

	// Example of an invalid profile URL
	configURL := "github.com/chinmina/chinmina-bridge/docs/profile.yaml"
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
	_, err = github.GetProfile(context.Background(), gh, configURL)
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
	}{
		{
			configURL:      "github.com/chinmina/chinmina-bridge/docs/profile.yaml",
			expectedConfig: validProfile,
		},
		{
			configURL:      "github.com/chinmina/non-existent-profile.yaml",
			expectedConfig: github.ProfileConfig{},
		},
		{
			configURL:      "github.com/chinmina/chinmina-bridge/docs/invalid-profile.yaml",
			expectedConfig: github.ProfileConfig{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.configURL, func(t *testing.T) {
			result, _ := github.LoadProfile(context.Background(), gh, tc.configURL)
			assert.Equal(t, tc.expectedConfig, result)
		})
	}

}

func TestFetchProfile(t *testing.T) {

	router := http.NewServeMux()

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
	configURL := "github.com/chinmina/chinmina-bridge/docs/profile.yaml"
	fakeURL := "github.com/chinmina/chinmina-bridge/docs/fake-profile.yaml"
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
	// Test that we get an error attempting to load it before fetching
	_, err = gh.OrganizationProfile(context.Background())
	require.Error(t, err)

	err = gh.FetchOrganizationProfile(configURL)
	require.NoError(t, err)

	_, err = gh.OrganizationProfile(context.Background())
	require.NoError(t, err)

	err = gh.FetchOrganizationProfile(fakeURL)
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
			_, ok := profileConfig.HasProfile(tc.profileName)
			assert.Equal(t, ok, tc.expectedHasProfile)
			assert.Equal(t, profileConfig.HasRepository(tc.profileName, tc.repositoryName), tc.expectedHasRepository)
		})
	}
}
