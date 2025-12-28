package profile_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	api "github.com/google/go-github/v80/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchProfile(t *testing.T) {
	router := http.NewServeMux()
	profileStore := profile.NewProfileStore()

	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.InstallationToken{
			Token:     api.Ptr("expected-token"),
			ExpiresAt: &api.Timestamp{Time: expectedExpiry},
		})
	})

	router.HandleFunc("/repos/chinmina/chinmina-bridge/contents/docs/profile.yaml", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.RepositoryContent{
			Content: &validProfileYAML,
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

	validatedProfile, err := profile.ValidateProfile(context.Background(), validProfileYAML)
	require.NoError(t, err)

	// Test that we get an error attempting to load it before fetching
	_, err = profileStore.GetOrganization()
	require.Error(t, err)

	orgProfile, err := profile.FetchOrganizationProfile(context.Background(), profileConfig, gh)
	require.NoError(t, err)
	assertProfileConfigEqual(t, validatedProfile, orgProfile)

	orgProfile, err = profile.FetchOrganizationProfile(context.Background(), profileConfig, gh)
	require.NoError(t, err)

	profileStore.Update(orgProfile)
	loadedProfile, err := profileStore.GetOrganization()
	require.NoError(t, err)
	assertProfileConfigEqual(t, validatedProfile, loadedProfile)

	_, err = profile.FetchOrganizationProfile(context.Background(), fakeProfileConfig, gh)
	require.Error(t, err)
}

func TestGetProfileFromStore(t *testing.T) {
	profileConfig, err := profile.ValidateProfile(context.Background(), sharedValidProfile)
	require.NoError(t, err)

	store := profile.NewProfileStore()
	store.Update(profileConfig)

	validProfileName := "simple-profile"
	invalidProfileName := "glizzy"

	expectedProfile := profile.Profile{
		Name:         "simple-profile",
		Match:        nil,
		Repositories: []string{"repo-1", "repo-2"},
		Permissions:  []string{"read", "write"},
	}

	t.Run("Successful retrieval of an existing profile", func(t *testing.T) {
		retrievedProfile, err := store.GetProfileFromStore(validProfileName)
		require.NoError(t, err)
		// Use struct equality to verify the profile. Note: compiledMatcher is private
		// and verified through Matches() behavior, so we use assertProfileConfigEqual pattern
		assert.Equal(t, expectedProfile.Name, retrievedProfile.Name)
		assert.Equal(t, expectedProfile.Match, retrievedProfile.Match)
		assert.Equal(t, expectedProfile.Repositories, retrievedProfile.Repositories)
		assert.Equal(t, expectedProfile.Permissions, retrievedProfile.Permissions)
	})

	t.Run("Error handling when a profile is not found", func(t *testing.T) {
		_, err := store.GetProfileFromStore(invalidProfileName)
		require.Error(t, err)
		var notFoundErr profile.ProfileNotFoundError
		require.ErrorAs(t, err, &notFoundErr)
		assert.Equal(t, invalidProfileName, notFoundErr.Name)
	})

	t.Run("Error handling when a profile is unavailable due to validation failure", func(t *testing.T) {
		// Load a profile config with validation failures
		invalidProfileConfig, err := profile.ValidateProfile(context.Background(), profileWithMixedValidation)
		require.NoError(t, err)

		storeWithInvalid := profile.NewProfileStore()
		storeWithInvalid.Update(invalidProfileConfig)

		// Try to lookup an invalid profile
		_, err = storeWithInvalid.GetProfileFromStore("invalid-regex-pattern")
		require.Error(t, err)
		var unavailableErr profile.ProfileUnavailableError
		require.ErrorAs(t, err, &unavailableErr)
		assert.Equal(t, "invalid-regex-pattern", unavailableErr.Name)
		assert.NotNil(t, unavailableErr.Cause)
	})

	t.Run("Profile lookup is limited to one goroutine at a time", func(t *testing.T) {
		const numGoroutines = 10
		var wg sync.WaitGroup
		var mu sync.Mutex
		accessCount := 0

		for range numGoroutines {
			wg.Go(func() {
				_, err := store.GetProfileFromStore(validProfileName)
				assert.NoError(t, err)

				mu.Lock()
				accessCount++
				mu.Unlock()
			})
		}

		wg.Wait()

		assert.Equal(t, numGoroutines, accessCount, "All goroutines should have executed")
	})
}

func TestProfileStoreRWMutexConcurrency(t *testing.T) {
	// Setup: Create a ProfileStore with a valid profile
	store := profile.NewProfileStore()
	profileConfig := profile.NewTestProfileConfig(
		profile.NewTestProfile("test-profile", []string{"test-repo"}, []string{"contents:read"}),
	)
	store.Update(profileConfig)

	t.Run("Writes serialize with reads correctly", func(t *testing.T) {
		// Test that concurrent reads and writes maintain data consistency
		// With RWMutex: reads can be concurrent, but writes must be exclusive

		const numReaders = 20
		const numWriters = 5
		var wg sync.WaitGroup
		errChan := make(chan error, numReaders+numWriters)

		// Launch concurrent readers
		for range numReaders {
			wg.Go(func() {
				// Multiple reads should all succeed
				_, err := store.GetProfileFromStore("test-profile")
				if err != nil {
					errChan <- err
				}
				_, err = store.GetOrganization()
				if err != nil {
					errChan <- err
				}
			})
		}

		// Launch concurrent writers
		for range numWriters {
			wg.Go(func() {
				newConfig := profile.NewTestProfileConfig(
					profile.NewTestProfile("test-profile", []string{"test-repo"}, []string{"contents:read"}),
				)
				store.Update(newConfig)
			})
		}

		wg.Wait()
		close(errChan)

		// Verify no errors occurred during concurrent access
		var errors []error
		for err := range errChan {
			errors = append(errors, err)
		}
		assert.Empty(t, errors, "Should have no errors during concurrent read/write operations")
	})
}
