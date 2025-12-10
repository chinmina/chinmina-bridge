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
	api "github.com/google/go-github/v80/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/profile/valid_profile.yaml
var profile string

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

// Helper function to compare ProfileConfigs without comparing CompiledMatcher function pointers
func assertProfileConfigEqual(t *testing.T, expected, actual github.ProfileConfig) {
	t.Helper()

	// Compare organization defaults
	assert.Equal(t, expected.Organization.Defaults.Permissions, actual.Organization.Defaults.Permissions)

	// Compare number of profiles
	assert.Len(t, actual.Organization.Profiles, len(expected.Organization.Profiles))

	// Compare each profile excluding CompiledMatcher
	for i, expectedProf := range expected.Organization.Profiles {
		if i >= len(actual.Organization.Profiles) {
			break
		}
		actualProf := actual.Organization.Profiles[i]

		assert.Equal(t, expectedProf.Name, actualProf.Name, "profile name mismatch at index %d", i)
		assert.Equal(t, expectedProf.Match, actualProf.Match, "match rules mismatch for profile %s", expectedProf.Name)
		assert.Equal(t, expectedProf.Repositories, actualProf.Repositories, "repositories mismatch for profile %s", expectedProf.Name)
		assert.Equal(t, expectedProf.Permissions, actualProf.Permissions, "permissions mismatch for profile %s", expectedProf.Name)
		assert.NotNil(t, actualProf.CompiledMatcher, "compiled matcher should not be nil for profile %s", actualProf.Name)
	}
}

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
			Token:     api.Ptr("expected-token"),
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
	_, err = github.GetProfile(context.Background(), gh, profileConfig)
	require.Error(t, err)
	assert.ErrorContains(t, err, ": 418")
}

// Test that the profile that is loaded is valid
func TestValidProfile(t *testing.T) {
	_, _, err := github.ValidateProfile(context.Background(), profile)

	require.NoError(t, err)
}

// Test case where the profile that is loaded is invalid
func TestInvalidProfile(t *testing.T) {
	_, _, err := github.ValidateProfile(context.Background(), invalidProfile)

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

	validProfile, _, _ := github.ValidateProfile(context.Background(), profile)

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
			result, _, err := github.LoadProfile(context.Background(), gh, tc.config)
			tc.errorAssertion(t, err)
			if err == nil {
				assertProfileConfigEqual(t, tc.expectedConfig, result)
			}
		})
	}
}

func TestFetchProfile(t *testing.T) {
	router := http.NewServeMux()
	profileStore := github.NewProfileStore()

	expectedExpiry := time.Date(1980, 01, 01, 0, 0, 0, 0, time.UTC)

	router.HandleFunc("/app/installations/{installationID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, &api.InstallationToken{
			Token:     api.Ptr("expected-token"),
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

	validatedProfile, _, err := github.ValidateProfile(context.Background(), profile)
	require.NoError(t, err)

	// Test that we get an error attempting to load it before fetching
	_, err = profileStore.GetOrganization()
	require.Error(t, err)

	orgProfile, _, err := github.FetchOrganizationProfile(context.Background(), profileConfig, gh)
	require.NoError(t, err)
	assertProfileConfigEqual(t, validatedProfile, orgProfile)

	orgProfile, _, err = github.FetchOrganizationProfile(context.Background(), profileConfig, gh)
	require.NoError(t, err)

	profileStore.Update(&orgProfile, nil)
	loadedProfile, err := profileStore.GetOrganization()
	require.NoError(t, err)
	assertProfileConfigEqual(t, validatedProfile, loadedProfile)

	_, _, err = github.FetchOrganizationProfile(context.Background(), fakeProfileConfig, gh)
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
			profileConfig, _, err := github.ValidateProfile(context.Background(), profile)
			require.NoError(t, err)

			p, ok := profileConfig.LookupProfile(tc.profileName)
			assert.Equal(t, ok, tc.expectedHasProfile)
			assert.Equal(t, p.HasRepository(tc.repositoryName), tc.expectedHasRepository)
		})
	}
}
func TestGetProfileFromStore(t *testing.T) {
	profileConfig, _, err := github.ValidateProfile(context.Background(), sharedValidProfile)
	require.NoError(t, err)

	store := github.NewProfileStore()
	store.Update(&profileConfig, nil)

	validProfileName := "simple-profile"
	invalidProfileName := "glizzy"

	expectedProfile := github.Profile{
		Name:         "simple-profile",
		Match:        nil,
		Repositories: []string{"repo-1", "repo-2"},
		Permissions:  []string{"read", "write"},
	}

	t.Run("Successful retrieval of an existing profile", func(t *testing.T) {
		retrievedProfile, err := store.GetProfileFromStore(validProfileName)
		require.NoError(t, err)
		assert.Equal(t, expectedProfile.Name, retrievedProfile.Name)
		assert.Equal(t, expectedProfile.Match, retrievedProfile.Match)
		assert.Equal(t, expectedProfile.Repositories, retrievedProfile.Repositories)
		assert.Equal(t, expectedProfile.Permissions, retrievedProfile.Permissions)
		assert.NotNil(t, retrievedProfile.CompiledMatcher)
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

func TestGetDefaultPermissions(t *testing.T) {
	testCases := []struct {
		name     string
		config   github.ProfileConfig
		expected []string
	}{
		{
			name: "returns configured permissions when present",
			config: github.ProfileConfig{
				Organization: struct {
					Defaults struct {
						Permissions []string `yaml:"permissions"`
					} `yaml:"defaults"`
					Profiles []github.Profile `yaml:"profiles"`
				}{
					Defaults: struct {
						Permissions []string `yaml:"permissions"`
					}{
						Permissions: []string{"contents:read", "pull_requests:write"},
					},
				},
			},
			expected: []string{"contents:read", "pull_requests:write"},
		},
		{
			name: "returns fallback when defaults section not configured",
			config: github.ProfileConfig{
				Organization: struct {
					Defaults struct {
						Permissions []string `yaml:"permissions"`
					} `yaml:"defaults"`
					Profiles []github.Profile `yaml:"profiles"`
				}{},
			},
			expected: []string{"contents:read"},
		},
		{
			name: "returns fallback when permissions array is empty",
			config: github.ProfileConfig{
				Organization: struct {
					Defaults struct {
						Permissions []string `yaml:"permissions"`
					} `yaml:"defaults"`
					Profiles []github.Profile `yaml:"profiles"`
				}{
					Defaults: struct {
						Permissions []string `yaml:"permissions"`
					}{
						Permissions: []string{},
					},
				},
			},
			expected: []string{"contents:read"},
		},
		{
			name: "returns single custom permission",
			config: github.ProfileConfig{
				Organization: struct {
					Defaults struct {
						Permissions []string `yaml:"permissions"`
					} `yaml:"defaults"`
					Profiles []github.Profile `yaml:"profiles"`
				}{
					Defaults: struct {
						Permissions []string `yaml:"permissions"`
					}{
						Permissions: []string{"packages:read"},
					},
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

	profileConfig, _, err := github.ValidateProfile(ctx, profileWithDefaults)
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

	profileConfig, _, err := github.ValidateProfile(ctx, profileWithoutDefaults)
	require.NoError(t, err)

	// Backward compatibility: profile without defaults should still load and use fallback
	assert.Empty(t, profileConfig.Organization.Defaults.Permissions)
	assert.Equal(t, []string{"contents:read"}, profileConfig.GetDefaultPermissions())
	assert.Len(t, profileConfig.Organization.Profiles, 1)
}

func TestValidateMatchRule(t *testing.T) {
	testCases := []struct {
		name          string
		rule          github.MatchRule
		expectedError string
	}{
		{
			name: "valid rule with value",
			rule: github.MatchRule{
				Claim: "pipeline_slug",
				Value: "silk-prod",
			},
			expectedError: "",
		},
		{
			name: "valid rule with valuePattern",
			rule: github.MatchRule{
				Claim:        "pipeline_slug",
				ValuePattern: "silk-.*",
			},
			expectedError: "",
		},
		{
			name: "valid rule with agent_tag prefix",
			rule: github.MatchRule{
				Claim: "agent_tag:environment",
				Value: "production",
			},
			expectedError: "",
		},
		{
			name: "error when both value and valuePattern specified",
			rule: github.MatchRule{
				Claim:        "pipeline_slug",
				Value:        "silk-prod",
				ValuePattern: "silk-.*",
			},
			expectedError: "exactly one of 'value' or 'valuePattern' must be specified",
		},
		{
			name: "error when neither value nor valuePattern specified",
			rule: github.MatchRule{
				Claim: "pipeline_slug",
			},
			expectedError: "one of 'value' or 'valuePattern' is required",
		},
		{
			name: "error when claim is not allowed",
			rule: github.MatchRule{
				Claim: "invalid_claim",
				Value: "test",
			},
			expectedError: "claim \"invalid_claim\" is not allowed for matching",
		},
		{
			name: "error when claim is step_key (not allowed)",
			rule: github.MatchRule{
				Claim: "step_key",
				Value: "test",
			},
			expectedError: "claim \"step_key\" is not allowed for matching",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := github.ValidateMatchRule(tc.rule)
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
			result := github.IsAllowedClaim(tc.claim)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateProfileWithMatchRules(t *testing.T) {
	ctx := context.Background()

	profileConfig, failedProfiles, err := github.ValidateProfile(ctx, profileWithMatchRules)
	require.NoError(t, err)
	assert.Empty(t, failedProfiles, "valid profile should not have failures")

	// Verify we have all expected profiles
	assert.Len(t, profileConfig.Organization.Profiles, 4)

	// Test profile with exact match rule
	productionDeploy, ok := profileConfig.LookupProfile("production-deploy")
	require.True(t, ok)
	assert.Equal(t, "production-deploy", productionDeploy.Name)
	assert.Equal(t, []github.MatchRule{
		{
			Claim: "pipeline_slug",
			Value: "silk-prod",
		},
	}, productionDeploy.Match)
	assert.Equal(t, []string{"acme/silk"}, productionDeploy.Repositories)
	assert.Equal(t, []string{"contents:write"}, productionDeploy.Permissions)
	assert.NotNil(t, productionDeploy.CompiledMatcher, "compiled matcher should be set")

	// Test profile with regex pattern match
	stagingDeploy, ok := profileConfig.LookupProfile("staging-deploy")
	require.True(t, ok)
	assert.Equal(t, "staging-deploy", stagingDeploy.Name)
	assert.Equal(t, []github.MatchRule{
		{
			Claim:        "pipeline_slug",
			ValuePattern: "(silk|cotton)-(staging|stg)",
		},
	}, stagingDeploy.Match)
	assert.Equal(t, []string{"acme/silk", "acme/cotton"}, stagingDeploy.Repositories)
	assert.Equal(t, []string{"contents:write"}, stagingDeploy.Permissions)
	assert.NotNil(t, stagingDeploy.CompiledMatcher, "compiled matcher should be set")

	// Test profile with multiple match rules (AND logic)
	productionSilkOnly, ok := profileConfig.LookupProfile("production-silk-only")
	require.True(t, ok)
	assert.Equal(t, "production-silk-only", productionSilkOnly.Name)
	assert.Equal(t, []github.MatchRule{
		{
			Claim:        "pipeline_slug",
			ValuePattern: "silk-.*",
		},
		{
			Claim: "build_branch",
			Value: "main",
		},
	}, productionSilkOnly.Match)
	assert.Equal(t, []string{"acme/silk"}, productionSilkOnly.Repositories)
	assert.Equal(t, []string{"contents:write"}, productionSilkOnly.Permissions)
	assert.NotNil(t, productionSilkOnly.CompiledMatcher, "compiled matcher should be set")

	// Test profile with no match rules (empty array)
	sharedUtilities, ok := profileConfig.LookupProfile("shared-utilities-read")
	require.True(t, ok)
	assert.Equal(t, "shared-utilities-read", sharedUtilities.Name)
	assert.Equal(t, []github.MatchRule{}, sharedUtilities.Match)
	assert.Equal(t, []string{"acme/shared-utilities"}, sharedUtilities.Repositories)
	assert.Equal(t, []string{"contents:read"}, sharedUtilities.Permissions)
	assert.NotNil(t, sharedUtilities.CompiledMatcher, "compiled matcher should be set even for empty match rules")
}

// TestGracefulDegradation verifies that profile validation implements graceful degradation:
// - Invalid profiles are dropped with warnings
// - Valid profiles remain accessible
// - Failed profiles are tracked for diagnostics
func TestGracefulDegradation(t *testing.T) {
	ctx := context.Background()

	profileConfig, failedProfiles, err := github.ValidateProfile(ctx, profileWithMixedValidation)
	require.NoError(t, err, "ValidateProfile should not return an error even with invalid profiles")

	// We should have 3 failed profiles
	assert.Len(t, failedProfiles, 3, "expected 3 failed profiles")

	// Verify failed profiles are tracked with errors
	assert.Contains(t, failedProfiles, "invalid-both-match-types")
	assert.Contains(t, failedProfiles, "invalid-disallowed-claim")
	assert.Contains(t, failedProfiles, "invalid-regex-pattern")

	// Verify error messages contain the reasons
	assert.ErrorContains(t, failedProfiles["invalid-both-match-types"], "exactly one")
	assert.ErrorContains(t, failedProfiles["invalid-disallowed-claim"], "not allowed")
	assert.ErrorContains(t, failedProfiles["invalid-regex-pattern"], "invalid regex")

	// Only valid profiles should be in the config
	assert.Len(t, profileConfig.Organization.Profiles, 3, "expected 3 valid profiles")

	// Verify valid profiles are accessible
	validNames := []string{"valid-production", "valid-staging", "valid-no-match"}
	for _, name := range validNames {
		prof, ok := profileConfig.LookupProfile(name)
		assert.True(t, ok, "valid profile %q should be accessible", name)
		assert.NotNil(t, prof.CompiledMatcher, "profile %q should have compiled matcher", name)
	}

	// Verify invalid profiles are not accessible
	invalidNames := []string{"invalid-both-match-types", "invalid-disallowed-claim", "invalid-regex-pattern"}
	for _, name := range invalidNames {
		_, ok := profileConfig.LookupProfile(name)
		assert.False(t, ok, "invalid profile %q should not be accessible", name)
	}

	// Verify that the valid profiles have working matchers
	// We can't test actual matching without BuildkiteClaims implementation,
	// but we can verify the matchers are compiled
	validProd, _ := profileConfig.LookupProfile("valid-production")
	assert.NotNil(t, validProd.CompiledMatcher)
	assert.Equal(t, "valid-production", validProd.Name)
	assert.Equal(t, []string{"acme/silk"}, validProd.Repositories)
}
