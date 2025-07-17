package github_test

import (
	"context"
	_ "embed"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	api "github.com/google/go-github/v73/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed profile/valid_profile.yaml
var profile string

//go:embed profile/invalid_profile.yaml
var invalidProfile string

// Test that the triplet logic works as expected
func TestTripletDecomposition(t *testing.T) {
	// Example of a valid profile URL
	profileConfig := "chinmina:chinmina-bridge:docs/profile.yaml"
	// Test that the profile triplet is valid

	owner, repo, path := github.DecomposePath(profileConfig)
	assert.Equal(t, "chinmina", owner)
	assert.Equal(t, "chinmina-bridge", repo)
	assert.Equal(t, "docs/profile.yaml", path)

	// Example of an invalid profile triplet
	profileConfig = "chinmina:profile.yaml"

	// Test that the profile triplet is invalid (path contains missing owner/repo)
	owner, repo, path = github.DecomposePath(profileConfig)
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

	// Example of a valid profile triplet
	profileConfig := "chinmina:chinmina-bridge:docs/profile.yaml"
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
	profile, err = github.GetProfile(context.Background(), gh, profileConfig)
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

	// Example of an invalid profile triplet
	profileConfig := "chinmina:chinmina-bridge:docs/profile.yaml"

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
	_, err = github.GetProfile(context.Background(), gh, profileConfig)
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
		config         string
		expectedConfig github.ProfileConfig
		errorAssertion assert.ErrorAssertionFunc
	}{
		{
			config:         "chinmina:chinmina-bridge:docs/profile.yaml",
			expectedConfig: validProfile,
			errorAssertion: assert.NoError,
		},
		{
			config:         "chinmina:non-existent-profile.yaml",
			expectedConfig: github.ProfileConfig{},
			errorAssertion: assert.Error,
		},
		{
			config:         "chinmina:chinmina-bridge:docs/invalid-profile.yaml",
			expectedConfig: github.ProfileConfig{},
			errorAssertion: assert.Error,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.config, func(t *testing.T) {
			result, err := github.LoadProfile(context.Background(), gh, tc.config)
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

	profileConfig := "chinmina:chinmina-bridge:docs/profile.yaml"

	fakeProfileConfig := "chinmina:chinmina-bridge:docs/fake-profile.yaml"

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

	orgProfile, err := github.FetchOrganizationProfile(context.Background(), profileConfig, gh)
	require.NoError(t, err)
	assert.Equal(t, validatedProfile, orgProfile)

	orgProfile, err = github.FetchOrganizationProfile(context.Background(), profileConfig, gh)
	require.NoError(t, err)

	profileStore.Update(&orgProfile)
	loadedProfile, err := profileStore.GetOrganization()
	require.NoError(t, err)
	assert.Equal(t, loadedProfile, validatedProfile)

	_, err = github.FetchOrganizationProfile(context.Background(), fakeProfileConfig, gh)
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

			p, ok := profileConfig.LookupProfile(tc.profileName)
			assert.Equal(t, ok, tc.expectedHasProfile)
			assert.Equal(t, p.HasRepository(tc.repositoryName), tc.expectedHasRepository)
		})
	}
}
func TestGetProfileFromStore(t *testing.T) {

	store := testhelpers.CreateTestProfileStore()
	validProfileName := "simple-profile"
	invalidProfileName := "glizzy"

	expectedProfile := github.Profile{
		Name:         "simple-profile",
		Repositories: []string{"repo-1", "repo-2"},
		Permissions:  []string{"read", "write"},
	}

	t.Run("Successful retrieval of an existing profile", func(t *testing.T) {
		retrievedProfile, err := store.GetProfileFromStore(validProfileName)
		require.NoError(t, err)
		assert.Equal(t, expectedProfile, retrievedProfile)
	})

	t.Run("Error handling when a profile is not found", func(t *testing.T) {
		_, err := store.GetProfileFromStore(invalidProfileName)
		require.Error(t, err)
		assert.EqualError(t, err, "profile not found")
	})

	t.Run("Profile lookup is limited to one goroutine at a time", func(t *testing.T) {
		const numGoroutines = 10
		var wg sync.WaitGroup
		var mu sync.Mutex
		accessCount := 0

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				_, err := store.GetProfileFromStore(validProfileName)
				assert.NoError(t, err)

				mu.Lock()
				accessCount++
				mu.Unlock()
			}()
		}

		wg.Wait()

		assert.Equal(t, numGoroutines, accessCount, "All goroutines should have executed")
	})
}
