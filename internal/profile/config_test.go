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
	loadedYAML, err := profile.GetProfile(context.Background(), gh, profileConfig)
	require.NoError(t, err)
	assert.Equal(t, validProfileYAML, loadedYAML)
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

	validProfileConfig, _ := profile.ValidateProfile(context.Background(), validProfileYAML)
	expectedDigest := validProfileConfig.Digest()

	testCases := []struct {
		config         string
		expectedDigest string
		errorAssertion assert.ErrorAssertionFunc
	}{
		{
			config:         "chinmina:chinmina-bridge:docs/profile.yaml",
			expectedDigest: expectedDigest,
			errorAssertion: assert.NoError,
		},
		{
			config:         "chinmina:non-existent-profile.yaml",
			expectedDigest: "",
			errorAssertion: assert.Error,
		},
		{
			config:         "chinmina:chinmina-bridge:docs/invalid-profile.yaml",
			expectedDigest: "",
			errorAssertion: assert.Error,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.config, func(t *testing.T) {
			result, err := profile.LoadProfile(context.Background(), gh, tc.config)
			tc.errorAssertion(t, err)
			if err == nil {
				assert.Equal(t, tc.expectedDigest, result.Digest())
				assert.True(t, result.IsLoaded())
			}
		})
	}
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

func TestProfileConfigDigest(t *testing.T) {
	t.Run("digest is populated by ValidateProfile", func(t *testing.T) {
		config, err := profile.ValidateProfile(context.Background(), validProfileYAML)
		require.NoError(t, err)

		digest := config.Digest()
		assert.NotEmpty(t, digest, "digest should be populated")
		assert.Len(t, digest, 64, "SHA256 hex string should be 64 characters")
	})

	t.Run("identical YAML produces identical digests", func(t *testing.T) {
		config1, err := profile.ValidateProfile(context.Background(), validProfileYAML)
		require.NoError(t, err)

		config2, err := profile.ValidateProfile(context.Background(), validProfileYAML)
		require.NoError(t, err)

		assert.Equal(t, config1.Digest(), config2.Digest())
	})

	t.Run("different YAML produces different digests", func(t *testing.T) {
		config1, err := profile.ValidateProfile(context.Background(), validProfileYAML)
		require.NoError(t, err)

		config2, err := profile.ValidateProfile(context.Background(), profileWithDefaults)
		require.NoError(t, err)

		assert.NotEqual(t, config1.Digest(), config2.Digest())
	})
}

// testClaimLookup implements ClaimValueLookup for testing CompileProfiles.
type testClaimLookup struct {
	claims map[string]string
}

func (t testClaimLookup) Lookup(claim string) (string, error) {
	if t.claims == nil {
		return "", jwt.ErrClaimNotFound
	}
	value, found := t.claims[claim]
	if !found {
		return "", jwt.ErrClaimNotFound
	}
	return value, nil
}

func TestCompileProfiles(t *testing.T) {
	t.Run("converts valid profiles to runtime format", func(t *testing.T) {
		// Create a ProfileConfig with valid profiles
		config, err := profile.ValidateProfile(context.Background(), `
organization:
  profiles:
    - name: test-profile
      match:
        - claim: pipeline_slug
          value: my-pipeline
      repositories:
        - chinmina/chinmina-bridge
      permissions:
        - contents:read
`)
		require.NoError(t, err)

		// Compile to runtime format
		profiles := profile.CompileProfiles(config)

		// Verify the profile was converted
		assert.True(t, profiles.IsLoaded())
		assert.NotEmpty(t, profiles.Digest())

		// Verify we can retrieve the profile
		authProfile, err := profiles.GetOrgProfile("test-profile")
		require.NoError(t, err)
		assert.Equal(t, []string{"chinmina/chinmina-bridge"}, authProfile.Attrs.Repositories)
		assert.Equal(t, []string{"contents:read"}, authProfile.Attrs.Permissions)

		// Verify the matcher works
		claims := testClaimLookup{
			claims: map[string]string{
				"pipeline_slug": "my-pipeline",
			},
		}
		result := authProfile.Match(claims)
		assert.True(t, result.Matched)
	})

	t.Run("preserves invalid profiles", func(t *testing.T) {
		// Create a ProfileConfig with invalid profiles
		config, err := profile.ValidateProfile(context.Background(), `
organization:
  profiles:
    - name: valid-profile
      match:
        - claim: pipeline_slug
          value: my-pipeline
      repositories:
        - chinmina/chinmina-bridge
      permissions:
        - contents:read
    - name: invalid-profile
      match:
        - claim: pipeline_slug
          value: foo
          valuePattern: bar
      repositories:
        - chinmina/other-repo
      permissions:
        - contents:read
`)
		require.NoError(t, err)

		// Compile to runtime format
		profiles := profile.CompileProfiles(config)

		// Verify valid profile works
		_, err = profiles.GetOrgProfile("valid-profile")
		require.NoError(t, err)

		// Verify invalid profile returns ProfileUnavailableError
		_, err = profiles.GetOrgProfile("invalid-profile")
		require.Error(t, err)
		var unavailableErr profile.ProfileUnavailableError
		require.ErrorAs(t, err, &unavailableErr)
		assert.Equal(t, "invalid-profile", unavailableErr.Name)
	})

	t.Run("extracts pipeline defaults", func(t *testing.T) {
		config, err := profile.ValidateProfile(context.Background(), `
organization:
  defaults:
    permissions:
      - contents:read
      - metadata:read
  profiles:
    - name: test-profile
      match:
        - claim: pipeline_slug
          value: my-pipeline
      repositories:
        - chinmina/chinmina-bridge
      permissions:
        - contents:read
`)
		require.NoError(t, err)

		profiles := profile.CompileProfiles(config)

		defaults := profiles.GetPipelineDefaults()

		assert.Equal(t, []string{"contents:read", "metadata:read"}, defaults)
	})

	t.Run("falls back to default permissions when not configured", func(t *testing.T) {
		config, err := profile.ValidateProfile(context.Background(), `
organization:
  profiles:
    - name: test-profile
      match:
        - claim: pipeline_slug
          value: my-pipeline
      repositories:
        - chinmina/chinmina-bridge
      permissions:
        - contents:read
`)
		require.NoError(t, err)

		profiles := profile.CompileProfiles(config)

		defaults := profiles.GetPipelineDefaults()
		assert.Equal(t, []string{"contents:read"}, defaults)
	})

	t.Run("preserves digest", func(t *testing.T) {
		config, err := profile.ValidateProfile(context.Background(), `
organization:
  profiles:
    - name: test-profile
      match:
        - claim: pipeline_slug
          value: my-pipeline
      repositories:
        - chinmina/chinmina-bridge
      permissions:
        - contents:read
`)
		require.NoError(t, err)

		profiles := profile.CompileProfiles(config)

		assert.Equal(t, config.Digest(), profiles.Digest())
	})

	t.Run("matcher closure captures profile correctly", func(t *testing.T) {
		// This test ensures the closure captures the profile by value,
		// not by reference, which could cause issues with loop variables
		config, err := profile.ValidateProfile(context.Background(), `
organization:
  profiles:
    - name: profile-1
      match:
        - claim: pipeline_slug
          value: pipeline-1
      repositories:
        - chinmina/repo-1
      permissions:
        - contents:read
    - name: profile-2
      match:
        - claim: pipeline_slug
          value: pipeline-2
      repositories:
        - chinmina/repo-2
      permissions:
        - packages:write
`)
		require.NoError(t, err)

		profiles := profile.CompileProfiles(config)

		// Verify profile-1 matcher
		profile1, err := profiles.GetOrgProfile("profile-1")
		require.NoError(t, err)
		result1 := profile1.Match(testClaimLookup{
			claims: map[string]string{"pipeline_slug": "pipeline-1"},
		})
		assert.True(t, result1.Matched)
		assert.Equal(t, []string{"chinmina/repo-1"}, profile1.Attrs.Repositories)

		// Verify profile-2 matcher
		profile2, err := profiles.GetOrgProfile("profile-2")
		require.NoError(t, err)
		result2 := profile2.Match(testClaimLookup{
			claims: map[string]string{"pipeline_slug": "pipeline-2"},
		})
		assert.True(t, result2.Matched)
		assert.Equal(t, []string{"chinmina/repo-2"}, profile2.Attrs.Repositories)

		// Verify profile-1 doesn't match profile-2's claims
		result1Wrong := profile1.Match(testClaimLookup{
			claims: map[string]string{"pipeline_slug": "pipeline-2"},
		})
		assert.False(t, result1Wrong.Matched)
	})
}
