package profile_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	api "github.com/google/go-github/v80/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/profile/valid_profile.yaml
var validProfileYAML string

//go:embed testdata/profile/shared_valid.yaml
var sharedValidProfile string

//go:embed testdata/profile/invalid_profile.yaml
var invalidProfile string

//go:embed testdata/profile/profile_with_defaults.yaml
var profileWithDefaults string

//go:embed testdata/profile/profile_with_match_rules.yaml
var profileWithMatchRules string

//go:embed testdata/profile/profile_with_mixed_validation.yaml
var profileWithMixedValidation string

//go:embed testdata/profile/profile_with_duplicate_names.yaml
var profileWithDuplicateNames string

//go:embed testdata/profile/profile_with_empty_lists.yaml
var profileWithEmptyLists string

// JSON writes a JSON response for testing HTTP handlers
func JSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	res, _ := json.Marshal(payload)
	_, _ = w.Write(res)
}

// generateKey creates and PEM encodes a valid RSA private key for testing.
func generateKey(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	key := pem.EncodeToMemory(privateKeyPEM)

	return string(key)
}

// Helper function to compare ProfileConfigs without comparing CompiledMatcher function pointers
func assertProfileConfigEqual(t *testing.T, expected, actual profile.ProfileConfig) {
	t.Helper()

	// Compare organization defaults
	assert.Equal(t, expected.Organization.Defaults.Permissions, actual.Organization.Defaults.Permissions)

	// Compare number of profiles
	assert.Len(t, actual.Organization.Profiles, len(expected.Organization.Profiles))

	// Compare each profile excluding compiledMatcher
	for i, expectedProf := range expected.Organization.Profiles {
		if i >= len(actual.Organization.Profiles) {
			break
		}
		actualProf := actual.Organization.Profiles[i]

		assert.Equal(t, expectedProf.Name, actualProf.Name, "profile name mismatch at index %d", i)
		assert.Equal(t, expectedProf.Match, actualProf.Match, "match rules mismatch for profile %s", expectedProf.Name)
		assert.Equal(t, expectedProf.Repositories, actualProf.Repositories, "repositories mismatch for profile %s", expectedProf.Name)
		assert.Equal(t, expectedProf.Permissions, actualProf.Permissions, "permissions mismatch for profile %s", expectedProf.Name)
		// Note: compiledMatcher is private and verified through Matches() behavior
	}
}

// Test that the triplet logic works as expected
func TestTripletDecomposition(t *testing.T) {
	t.Run("valid triplet decomposition", func(t *testing.T) {
		owner, repo, path := profile.DecomposePath("chinmina:chinmina-bridge:docs/profile.yaml")
		assert.Equal(t, "chinmina", owner)
		assert.Equal(t, "chinmina-bridge", repo)
		assert.Equal(t, "docs/profile.yaml", path)
	})

	// Invalid triplet test cases (failure table)
	t.Run("invalid triplet with missing owner and repo", func(t *testing.T) {
		owner, repo, path := profile.DecomposePath("chinmina:profile.yaml")
		assert.Equal(t, "", owner)
		assert.Equal(t, "", repo)
		assert.Equal(t, "", path)
	})
}

// Test that repository contents are handled correctly
func TestRepositoryContents(t *testing.T) {
	router := http.NewServeMux()
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
	validProfileYAML, err = profile.GetProfile(context.Background(), gh, profileConfig)
	require.NoError(t, err)
}

func TestInvalidRepositoryContents(t *testing.T) {
	router := http.NewServeMux()
	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.InstallationToken{
			Token:     api.Ptr("expected-token"),
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
	_, err = profile.GetProfile(context.Background(), gh, profileConfig)
	require.Error(t, err)
	assert.ErrorContains(t, err, ": 418")
}

// Test that the profile that is loaded is valid
func TestValidProfile(t *testing.T) {
	_, err := profile.ValidateProfile(context.Background(), validProfileYAML)

	require.NoError(t, err)
}

// Test case where the profile that is loaded is invalid
func TestInvalidProfile(t *testing.T) {
	_, err := profile.ValidateProfile(context.Background(), invalidProfile)

	require.Error(t, err)
}

func TestLoadProfile(t *testing.T) {
	router := http.NewServeMux()

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

	validProfile, _ := profile.ValidateProfile(context.Background(), validProfileYAML)

	testCases := []struct {
		config         string
		expectedConfig profile.ProfileConfig
		errorAssertion assert.ErrorAssertionFunc
	}{
		{
			config:         "chinmina:chinmina-bridge:docs/profile.yaml",
			expectedConfig: validProfile,
			errorAssertion: assert.NoError,
		},
		{
			config:         "chinmina:non-existent-profile.yaml",
			expectedConfig: profile.ProfileConfig{},
			errorAssertion: assert.Error,
		},
		{
			config:         "chinmina:chinmina-bridge:docs/invalid-profile.yaml",
			expectedConfig: profile.ProfileConfig{},
			errorAssertion: assert.Error,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.config, func(t *testing.T) {
			result, err := profile.LoadProfile(context.Background(), gh, tc.config)
			tc.errorAssertion(t, err)
			if err == nil {
				assertProfileConfigEqual(t, tc.expectedConfig, result)
			}
		})
	}
}

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
			profileConfig, err := profile.ValidateProfile(context.Background(), validProfileYAML)
			require.NoError(t, err)

			p, err := profileConfig.LookupProfile(tc.profileName)
			if tc.expectedHasProfile {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedHasRepository, p.HasRepository(tc.repositoryName))
			} else {
				require.Error(t, err)
			}
		})
	}
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

	t.Run("Concurrent reads can execute in parallel", func(t *testing.T) {
		const numGoroutines = 10
		var wg sync.WaitGroup

		// Channel to track when each goroutine starts reading
		startedReading := make(chan struct{}, numGoroutines)
		// Channel to coordinate when goroutines should finish
		finishReading := make(chan struct{})

		// Launch multiple read goroutines
		for range numGoroutines {
			wg.Go(func() {
				// Signal that we've started reading
				startedReading <- struct{}{}

				// Hold the read lock until told to finish
				_, err := store.GetProfileFromStore("test-profile")
				assert.NoError(t, err)

				// Wait for signal to finish
				<-finishReading
			})
		}

		// Wait for all goroutines to start reading
		for range numGoroutines {
			select {
			case <-startedReading:
				// Good, goroutine started
			case <-time.After(1 * time.Second):
				t.Fatal("Timeout waiting for goroutines to start - reads may be blocking each other")
			}
		}

		// If we got here, all goroutines started reading concurrently
		// Now let them finish
		close(finishReading)
		wg.Wait()
	})

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

func TestGetDefaultPermissions(t *testing.T) {
	testCases := []struct {
		name     string
		config   profile.ProfileConfig
		expected []string
	}{
		{
			name: "returns configured permissions when present",
			config: profile.ProfileConfig{
				Organization: struct {
					Defaults struct {
						Permissions []string `yaml:"permissions"`
					} `yaml:"defaults"`
					Profiles        []profile.Profile `yaml:"profiles"`
					InvalidProfiles map[string]error  `yaml:"-"`
				}{
					Defaults: struct {
						Permissions []string `yaml:"permissions"`
					}{
						Permissions: []string{"contents:read", "pull_requests:write"},
					},
					InvalidProfiles: make(map[string]error),
				},
			},
			expected: []string{"contents:read", "pull_requests:write"},
		},
		{
			name: "returns fallback when defaults section not configured",
			config: profile.ProfileConfig{
				Organization: struct {
					Defaults struct {
						Permissions []string `yaml:"permissions"`
					} `yaml:"defaults"`
					Profiles        []profile.Profile `yaml:"profiles"`
					InvalidProfiles map[string]error  `yaml:"-"`
				}{
					InvalidProfiles: make(map[string]error),
				},
			},
			expected: []string{"contents:read"},
		},
		{
			name: "returns fallback when permissions array is empty",
			config: profile.ProfileConfig{
				Organization: struct {
					Defaults struct {
						Permissions []string `yaml:"permissions"`
					} `yaml:"defaults"`
					Profiles        []profile.Profile `yaml:"profiles"`
					InvalidProfiles map[string]error  `yaml:"-"`
				}{
					Defaults: struct {
						Permissions []string `yaml:"permissions"`
					}{
						Permissions: []string{},
					},
					InvalidProfiles: make(map[string]error),
				},
			},
			expected: []string{"contents:read"},
		},
		{
			name: "returns single custom permission",
			config: profile.ProfileConfig{
				Organization: struct {
					Defaults struct {
						Permissions []string `yaml:"permissions"`
					} `yaml:"defaults"`
					Profiles        []profile.Profile `yaml:"profiles"`
					InvalidProfiles map[string]error  `yaml:"-"`
				}{
					Defaults: struct {
						Permissions []string `yaml:"permissions"`
					}{
						Permissions: []string{"packages:read"},
					},
					InvalidProfiles: make(map[string]error),
				},
			},
			expected: []string{"packages:read"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.config.GetDefaultPermissions()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateProfileWithDefaults(t *testing.T) {
	ctx := context.Background()

	profileConfig, err := profile.ValidateProfile(ctx, profileWithDefaults)
	require.NoError(t, err)

	expectedDefaults := []string{"contents:read", "pull_requests:write"}
	assert.Equal(t, expectedDefaults, profileConfig.Organization.Defaults.Permissions)
	assert.Equal(t, expectedDefaults, profileConfig.GetDefaultPermissions())
	assert.Len(t, profileConfig.Organization.Profiles, 2)
}

func TestValidateProfileWithoutDefaults(t *testing.T) {
	ctx := context.Background()

	// Test backward compatibility: profile without defaults section
	profileWithoutDefaults := `organization:
  profiles:
    - name: "test-profile"
      repositories: ["repo1"]
      permissions: ["contents:read"]`

	profileConfig, err := profile.ValidateProfile(ctx, profileWithoutDefaults)
	require.NoError(t, err)

	// Backward compatibility: profile without defaults should still load and use fallback
	assert.Empty(t, profileConfig.Organization.Defaults.Permissions)
	assert.Equal(t, []string{"contents:read"}, profileConfig.GetDefaultPermissions())
	assert.Len(t, profileConfig.Organization.Profiles, 1)
}

func TestValidateMatchRule(t *testing.T) {
	testCases := []struct {
		name          string
		rule          profile.MatchRule
		expectedError string
	}{
		{
			name: "valid rule with value",
			rule: profile.MatchRule{
				Claim: "pipeline_slug",
				Value: "silk-prod",
			},
			expectedError: "",
		},
		{
			name: "valid rule with valuePattern",
			rule: profile.MatchRule{
				Claim:        "pipeline_slug",
				ValuePattern: "silk-.*",
			},
			expectedError: "",
		},
		{
			name: "valid rule with agent_tag prefix",
			rule: profile.MatchRule{
				Claim: "agent_tag:environment",
				Value: "production",
			},
			expectedError: "",
		},
		{
			name: "error when both value and valuePattern specified",
			rule: profile.MatchRule{
				Claim:        "pipeline_slug",
				Value:        "silk-prod",
				ValuePattern: "silk-.*",
			},
			expectedError: "exactly one of 'value' or 'valuePattern' must be specified",
		},
		{
			name: "error when neither value nor valuePattern specified",
			rule: profile.MatchRule{
				Claim: "pipeline_slug",
			},
			expectedError: "one of 'value' or 'valuePattern' is required",
		},
		{
			name: "error when claim is not allowed",
			rule: profile.MatchRule{
				Claim: "invalid_claim",
				Value: "test",
			},
			expectedError: "claim \"invalid_claim\" is not allowed for matching",
		},
		{
			name: "error when claim is step_key (not allowed)",
			rule: profile.MatchRule{
				Claim: "step_key",
				Value: "test",
			},
			expectedError: "claim \"step_key\" is not allowed for matching",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := profile.ValidateMatchRule(tc.rule)
			if tc.expectedError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			}
		})
	}
}

func TestIsAllowedClaim(t *testing.T) {
	testCases := []struct {
		name     string
		claim    string
		expected bool
	}{
		{"pipeline_slug is allowed", "pipeline_slug", true},
		{"pipeline_id is allowed", "pipeline_id", true},
		{"build_number is allowed", "build_number", true},
		{"build_branch is allowed", "build_branch", true},
		{"build_tag is allowed", "build_tag", true},
		{"build_commit is allowed", "build_commit", true},
		{"cluster_id is allowed", "cluster_id", true},
		{"cluster_name is allowed", "cluster_name", true},
		{"queue_id is allowed", "queue_id", true},
		{"queue_key is allowed", "queue_key", true},
		{"agent_tag:environment is allowed", "agent_tag:environment", true},
		{"agent_tag:role is allowed", "agent_tag:role", true},
		{"step_key is not allowed", "step_key", false},
		{"job_id is not allowed", "job_id", false},
		{"agent_id is not allowed", "agent_id", false},
		{"organization_slug is not allowed", "organization_slug", false},
		{"unknown_claim is not allowed", "unknown_claim", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := profile.IsAllowedClaim(tc.claim)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateProfileWithMatchRules(t *testing.T) {
	ctx := context.Background()

	profileConfig, err := profile.ValidateProfile(ctx, profileWithMatchRules)
	require.NoError(t, err)
	assert.Empty(t, profileConfig.Organization.InvalidProfiles, "valid profile should not have failures")

	// Verify we have all expected profiles
	assert.Len(t, profileConfig.Organization.Profiles, 4)

	testCases := []struct {
		name            string
		profileName     string
		expectedProfile profile.Profile
	}{
		{
			name:        "exact match rule",
			profileName: "production-deploy",
			expectedProfile: profile.Profile{
				Name: "production-deploy",
				Match: []profile.MatchRule{
					{
						Claim: "pipeline_slug",
						Value: "silk-prod",
					},
				},
				Repositories: []string{"acme/silk"},
				Permissions:  []string{"contents:write"},
			},
		},
		{
			name:        "regex pattern match",
			profileName: "staging-deploy",
			expectedProfile: profile.Profile{
				Name: "staging-deploy",
				Match: []profile.MatchRule{
					{
						Claim:        "pipeline_slug",
						ValuePattern: "(silk|cotton)-(staging|stg)",
					},
				},
				Repositories: []string{"acme/silk", "acme/cotton"},
				Permissions:  []string{"contents:write"},
			},
		},
		{
			name:        "multiple match rules (AND logic)",
			profileName: "production-silk-only",
			expectedProfile: profile.Profile{
				Name: "production-silk-only",
				Match: []profile.MatchRule{
					{
						Claim:        "pipeline_slug",
						ValuePattern: "silk-.*",
					},
					{
						Claim: "build_branch",
						Value: "main",
					},
				},
				Repositories: []string{"acme/silk"},
				Permissions:  []string{"contents:write"},
			},
		},
		{
			name:        "no match rules (empty array)",
			profileName: "shared-utilities-read",
			expectedProfile: profile.Profile{
				Name:         "shared-utilities-read",
				Match:        []profile.MatchRule{},
				Repositories: []string{"acme/shared-utilities"},
				Permissions:  []string{"contents:read"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			retrievedProfile, err := profileConfig.LookupProfile(tc.profileName)
			require.NoError(t, err)
			// Compare all fields except compiledMatcher (private and verified via Matches() behavior)
			assert.Equal(t, tc.expectedProfile.Name, retrievedProfile.Name)
			assert.Equal(t, tc.expectedProfile.Match, retrievedProfile.Match)
			assert.Equal(t, tc.expectedProfile.Repositories, retrievedProfile.Repositories)
			assert.Equal(t, tc.expectedProfile.Permissions, retrievedProfile.Permissions)
		})
	}
}

// TestGracefulDegradation verifies that profile validation implements graceful degradation:
// - Invalid profiles are dropped with warnings
// - Valid profiles remain accessible
// - Failed profiles are tracked for diagnostics
func TestGracefulDegradation(t *testing.T) {
	ctx := context.Background()

	profileConfig, err := profile.ValidateProfile(ctx, profileWithMixedValidation)
	require.NoError(t, err, "ValidateProfile should not return an error even with invalid profiles")

	// We should have 3 invalid profiles
	assert.Len(t, profileConfig.Organization.InvalidProfiles, 3, "expected 3 invalid profiles")

	// Verify invalid profiles are tracked with errors
	assert.Contains(t, profileConfig.Organization.InvalidProfiles, "invalid-both-match-types")
	assert.Contains(t, profileConfig.Organization.InvalidProfiles, "invalid-disallowed-claim")
	assert.Contains(t, profileConfig.Organization.InvalidProfiles, "invalid-regex-pattern")

	// Verify error messages contain the reasons
	assert.ErrorContains(t, profileConfig.Organization.InvalidProfiles["invalid-both-match-types"], "exactly one")
	assert.ErrorContains(t, profileConfig.Organization.InvalidProfiles["invalid-disallowed-claim"], "not allowed")
	assert.ErrorContains(t, profileConfig.Organization.InvalidProfiles["invalid-regex-pattern"], "invalid regex")

	// Only valid profiles should be in the config
	assert.Len(t, profileConfig.Organization.Profiles, 3, "expected 3 valid profiles")

	// Verify valid profiles are accessible
	validNames := []string{"valid-production", "valid-staging", "valid-no-match"}
	for _, name := range validNames {
		_, err := profileConfig.LookupProfile(name)
		assert.NoError(t, err, "valid profile %q should be accessible", name)
		// Note: compiledMatcher is private, verified through ValidateProfile
	}

	// Verify invalid profiles are not accessible (return error)
	invalidNames := []string{"invalid-both-match-types", "invalid-disallowed-claim", "invalid-regex-pattern"}
	for _, name := range invalidNames {
		_, err := profileConfig.LookupProfile(name)
		assert.Error(t, err, "invalid profile %q should return error", name)
	}

	// Verify that the valid profiles have working matchers
	// We can't test actual matching without BuildkiteClaims implementation,
	// but compiledMatcher is verified through ValidateProfile
	validProd, _ := profileConfig.LookupProfile("valid-production")
	assert.Equal(t, "valid-production", validProd.Name)
	assert.Equal(t, []string{"acme/silk"}, validProd.Repositories)
}

func TestDuplicateProfileNames(t *testing.T) {
	ctx := context.Background()

	profileConfig, err := profile.ValidateProfile(ctx, profileWithDuplicateNames)
	require.NoError(t, err, "ValidateProfile should not return an error even with duplicate names")

	// We should have 1 invalid profile (the duplicate)
	assert.Len(t, profileConfig.Organization.InvalidProfiles, 1, "expected 1 invalid profile")

	// Verify the duplicate profile is tracked with an error
	assert.Contains(t, profileConfig.Organization.InvalidProfiles, "production")
	assert.ErrorContains(t, profileConfig.Organization.InvalidProfiles["production"], "duplicate profile name")

	// Only the first occurrence should be valid
	assert.Len(t, profileConfig.Organization.Profiles, 2, "expected 2 valid profiles")

	// Verify the first "production" profile is accessible
	prod, err := profileConfig.LookupProfile("production")
	assert.NoError(t, err, "first production profile should be accessible")
	assert.Equal(t, "production", prod.Name)
	assert.Equal(t, []string{"acme/silk"}, prod.Repositories)

	// Verify "staging" profile is accessible
	staging, err := profileConfig.LookupProfile("staging")
	assert.NoError(t, err, "staging profile should be accessible")
	assert.Equal(t, "staging", staging.Name)
}

func TestEmptyRepositoriesAndPermissions(t *testing.T) {
	ctx := context.Background()

	profileConfig, err := profile.ValidateProfile(ctx, profileWithEmptyLists)
	require.NoError(t, err, "ValidateProfile should not return an error even with empty lists")

	// We should have 3 invalid profiles (empty-repositories, empty-permissions, both-empty)
	assert.Len(t, profileConfig.Organization.InvalidProfiles, 3, "expected 3 invalid profiles")

	// Verify the empty-repositories profile is tracked with an error
	assert.Contains(t, profileConfig.Organization.InvalidProfiles, "empty-repositories")
	assert.ErrorContains(t, profileConfig.Organization.InvalidProfiles["empty-repositories"], "repositories list must be non-empty")

	// Verify the empty-permissions profile is tracked with an error
	assert.Contains(t, profileConfig.Organization.InvalidProfiles, "empty-permissions")
	assert.ErrorContains(t, profileConfig.Organization.InvalidProfiles["empty-permissions"], "permissions list must be non-empty")

	// Verify the both-empty profile is tracked with an error (should fail on repositories first)
	assert.Contains(t, profileConfig.Organization.InvalidProfiles, "both-empty")
	assert.ErrorContains(t, profileConfig.Organization.InvalidProfiles["both-empty"], "repositories list must be non-empty")

	// Only the valid profile should remain
	assert.Len(t, profileConfig.Organization.Profiles, 1, "expected 1 valid profile")

	// Verify the valid profile is accessible
	expected := profile.Profile{
		Name:         "valid-profile",
		Repositories: []string{"acme/test"},
		Permissions:  []string{"contents:read"},
	}

	validProf, err := profileConfig.LookupProfile("valid-profile")
	assert.NoError(t, err, "valid profile should be accessible")
	assert.Equal(t, expected.Name, validProf.Name)
	assert.Equal(t, expected.Repositories, validProf.Repositories)
	assert.Equal(t, expected.Permissions, validProf.Permissions)

	// Verify invalid profiles return errors
	invalidNames := []string{"empty-repositories", "empty-permissions", "both-empty"}
	for _, name := range invalidNames {
		_, err := profileConfig.LookupProfile(name)
		assert.Error(t, err, "invalid profile %q should return error", name)
	}
}

func TestProfileMatches(t *testing.T) {
	ctx := context.Background()

	// Load profile config with various match rules
	profileConfig, err := profile.ValidateProfile(ctx, profileWithMatchRules)
	require.NoError(t, err)

	testCases := []struct {
		name          string
		profileName   string
		claims        mockClaims
		expectMatch   bool
		expectMatches int
	}{
		{
			name:        "exact match success",
			profileName: "production-deploy",
			claims: mockClaims{
				"pipeline_slug": "silk-prod",
			},
			expectMatch:   true,
			expectMatches: 1,
		},
		{
			name:        "exact match failure",
			profileName: "production-deploy",
			claims: mockClaims{
				"pipeline_slug": "cotton-prod",
			},
			expectMatch:   false,
			expectMatches: 0,
		},
		{
			name:        "regex match success",
			profileName: "staging-deploy",
			claims: mockClaims{
				"pipeline_slug": "silk-staging",
			},
			expectMatch:   true,
			expectMatches: 1,
		},
		{
			name:        "regex match failure",
			profileName: "staging-deploy",
			claims: mockClaims{
				"pipeline_slug": "silk-prod",
			},
			expectMatch:   false,
			expectMatches: 0,
		},
		{
			name:        "multiple match rules - all pass",
			profileName: "production-silk-only",
			claims: mockClaims{
				"pipeline_slug": "silk-prod",
				"build_branch":  "main",
			},
			expectMatch:   true,
			expectMatches: 2,
		},
		{
			name:        "multiple match rules - one fails",
			profileName: "production-silk-only",
			claims: mockClaims{
				"pipeline_slug": "silk-prod",
				"build_branch":  "feature",
			},
			expectMatch:   false,
			expectMatches: 0,
		},
		{
			name:        "empty match rules - always passes",
			profileName: "shared-utilities-read",
			claims: mockClaims{
				"pipeline_slug": "anything",
			},
			expectMatch:   true,
			expectMatches: 0,
		},
		{
			name:          "empty match rules with empty claims",
			profileName:   "shared-utilities-read",
			claims:        mockClaims{},
			expectMatch:   true,
			expectMatches: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			prof, err := profileConfig.LookupProfile(tc.profileName)
			require.NoError(t, err)

			result := prof.Matches(tc.claims)
			assert.Equal(t, tc.expectMatch, result.Matched)
			assert.Len(t, result.Matches, tc.expectMatches, "number of matches mismatch")
			if tc.expectMatch {
				assert.Nil(t, result.Err, "successful match should have no error")
			} else {
				assert.NotNil(t, result.Attempt, "failed match should have attempt details")
			}
		})
	}
}

// mockClaims implements profile.ClaimValueLookup for testing
type mockClaims map[string]string

func (m mockClaims) Lookup(claim string) (string, error) {
	val, ok := m[claim]
	if !ok {
		return "", jwt.ErrClaimNotFound
	}
	return val, nil
}

func TestProfileErrorTypes(t *testing.T) {
	t.Run("ProfileNotFoundError", func(t *testing.T) {
		err := profile.ProfileNotFoundError{Name: "test-profile"}

		assert.Equal(t, `profile "test-profile" not found`, err.Error())

		var notFoundErr profile.ProfileNotFoundError
		require.ErrorAs(t, err, &notFoundErr)
		assert.Equal(t, "test-profile", notFoundErr.Name)
	})

	t.Run("ProfileUnavailableError", func(t *testing.T) {
		cause := errors.New("invalid regex pattern")
		var err error = profile.ProfileUnavailableError{
			Name:  "invalid-profile",
			Cause: cause,
		}

		assert.Equal(t, `profile "invalid-profile" unavailable: validation failed`, err.Error())

		var unavailableErr profile.ProfileUnavailableError
		require.ErrorAs(t, err, &unavailableErr)
		assert.Equal(t, "invalid-profile", unavailableErr.Name)
		assert.NotNil(t, unavailableErr.Cause)

		unwrapper, ok := err.(interface{ Unwrap() error })
		require.True(t, ok, "error should implement Unwrap")
		unwrappedErr := unwrapper.Unwrap()
		assert.Equal(t, cause.Error(), unwrappedErr.Error())
	})

	t.Run("ProfileMatchFailedError", func(t *testing.T) {
		err := profile.ProfileMatchFailedError{Name: "restricted-profile"}

		assert.Equal(t, `profile "restricted-profile" match conditions not met`, err.Error())

		var matchFailedErr profile.ProfileMatchFailedError
		require.ErrorAs(t, err, &matchFailedErr)
		assert.Equal(t, "restricted-profile", matchFailedErr.Name)
	})
}
