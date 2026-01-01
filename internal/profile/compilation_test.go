package profile

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateMatchRule_Success(t *testing.T) {
	tests := []struct {
		name string
		rule matchRule
	}{
		{
			name: "exact value match",
			rule: matchRule{
				Claim: "pipeline_slug",
				Value: "silk-prod",
			},
		},
		{
			name: "regex valuePattern",
			rule: matchRule{
				Claim:        "pipeline_slug",
				ValuePattern: ".*-staging",
			},
		},
		{
			name: "agent_tag prefix",
			rule: matchRule{
				Claim: "agent_tag:environment",
				Value: "production",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMatchRule(tt.rule)
			assert.NoError(t, err)
		})
	}
}

func TestValidateMatchRule_Failure(t *testing.T) {
	tests := []struct {
		name        string
		rule        matchRule
		expectedErr string
	}{
		{
			name: "both value and valuePattern specified",
			rule: matchRule{
				Claim:        "pipeline_slug",
				Value:        "silk-prod",
				ValuePattern: ".*-prod",
			},
			expectedErr: "exactly one of 'value' or 'valuePattern' must be specified",
		},
		{
			name: "neither value nor valuePattern specified",
			rule: matchRule{
				Claim: "pipeline_slug",
			},
			expectedErr: "one of 'value' or 'valuePattern' is required",
		},
		{
			name: "claim not in allowed list",
			rule: matchRule{
				Claim: "not_allowed_claim",
				Value: "test",
			},
			expectedErr: "not allowed for matching",
		},
		{
			name: "specifically disallowed claim - step_key",
			rule: matchRule{
				Claim: "step_key",
				Value: "test",
			},
			expectedErr: "not allowed for matching",
		},
		{
			name: "specifically disallowed claim - job_id",
			rule: matchRule{
				Claim: "job_id",
				Value: "test",
			},
			expectedErr: "not allowed for matching",
		},
		{
			name: "specifically disallowed claim - agent_id",
			rule: matchRule{
				Claim: "agent_id",
				Value: "test",
			},
			expectedErr: "not allowed for matching",
		},
		{
			name: "specifically disallowed claim - organization_slug",
			rule: matchRule{
				Claim: "organization_slug",
				Value: "test",
			},
			expectedErr: "not allowed for matching",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMatchRule(tt.rule)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestIsAllowedClaim_AllowedClaims(t *testing.T) {
	allowedClaims := []string{
		"pipeline_slug",
		"pipeline_id",
		"build_number",
		"build_branch",
		"build_tag",
		"build_commit",
		"cluster_id",
		"cluster_name",
		"queue_id",
		"queue_key",
		"agent_tag:environment",
		"agent_tag:region",
	}

	for _, claim := range allowedClaims {
		t.Run(claim, func(t *testing.T) {
			assert.True(t, IsAllowedClaim(claim))
		})
	}
}

func TestIsAllowedClaim_DisallowedClaims(t *testing.T) {
	disallowedClaims := []string{
		"step_key",
		"job_id",
		"agent_id",
		"organization_slug",
		"unknown_claim",
		"random_field",
	}

	for _, claim := range disallowedClaims {
		t.Run(claim, func(t *testing.T) {
			assert.False(t, IsAllowedClaim(claim))
		})
	}
}

func TestCompileMatchRules_Success(t *testing.T) {
	tests := []struct {
		name  string
		rules []matchRule
	}{
		{
			name: "single exact match",
			rules: []matchRule{
				{Claim: "pipeline_slug", Value: "silk-prod"},
			},
		},
		{
			name: "single regex match",
			rules: []matchRule{
				{Claim: "pipeline_slug", ValuePattern: ".*-staging"},
			},
		},
		{
			name: "multiple rules (AND logic)",
			rules: []matchRule{
				{Claim: "pipeline_slug", Value: "silk-prod"},
				{Claim: "build_branch", Value: "main"},
			},
		},
		{
			name:  "empty match rules",
			rules: []matchRule{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := compileMatchRules(tt.rules)
			require.NoError(t, err)
			assert.NotNil(t, matcher)
		})
	}
}

func TestCompileMatchRules_Failure(t *testing.T) {
	tests := []struct {
		name        string
		rules       []matchRule
		expectedErr string
	}{
		{
			name: "invalid rule - both match types",
			rules: []matchRule{
				{Claim: "pipeline_slug", Value: "silk-prod", ValuePattern: ".*-prod"},
			},
			expectedErr: "exactly one of 'value' or 'valuePattern' must be specified",
		},
		{
			name: "invalid rule - disallowed claim",
			rules: []matchRule{
				{Claim: "step_key", Value: "test"},
			},
			expectedErr: "not allowed for matching",
		},
		{
			name: "invalid regex pattern",
			rules: []matchRule{
				{Claim: "pipeline_slug", ValuePattern: "[invalid"},
			},
			expectedErr: "failed to compile regex pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := compileMatchRules(tt.rules)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
			assert.Nil(t, matcher)
		})
	}
}

func TestCompile_GracefulDegradation(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_mixed_validation.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")

	// Valid profiles should be accessible
	orgProfiles := profiles.orgProfiles

	validProfile, err := orgProfiles.Get("valid-production")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/silk"}, validProfile.Attrs.Repositories)

	validStaging, err := orgProfiles.Get("valid-staging")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/silk", "acme/cotton"}, validStaging.Attrs.Repositories)

	validNoMatch, err := orgProfiles.Get("valid-no-match")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/shared"}, validNoMatch.Attrs.Repositories)

	// Invalid profiles should return ProfileUnavailableError
	_, err = orgProfiles.Get("invalid-both-match-types")
	require.Error(t, err)
	var unavailErr ProfileUnavailableError
	require.ErrorAs(t, err, &unavailErr)
	assert.Equal(t, "invalid-both-match-types", unavailErr.Name)

	_, err = orgProfiles.Get("invalid-disallowed-claim")
	require.Error(t, err)
	require.ErrorAs(t, err, &unavailErr)
	assert.Equal(t, "invalid-disallowed-claim", unavailErr.Name)

	_, err = orgProfiles.Get("invalid-regex-pattern")
	require.Error(t, err)
	require.ErrorAs(t, err, &unavailErr)
	assert.Equal(t, "invalid-regex-pattern", unavailErr.Name)
}

func TestCompile_DuplicateNameHandling(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_duplicate_names.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")
	orgProfiles := profiles.orgProfiles

	// With duplicate names, the last profile with that name wins in the current implementation
	// (first is validated, but second's attributes overwrite in the profile map)
	profile, err := orgProfiles.Get("production")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/cotton"}, profile.Attrs.Repositories)

	// "staging" should also be accessible
	_, err = orgProfiles.Get("staging")
	require.NoError(t, err)
}

func TestCompile_EmptyListsHandling(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_empty_lists.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")
	orgProfiles := profiles.orgProfiles

	// Valid profile should be accessible
	_, err = orgProfiles.Get("valid-profile")
	require.NoError(t, err)

	// Profiles with empty lists should return ProfileUnavailableError
	_, err = orgProfiles.Get("empty-repositories")
	require.Error(t, err)
	var unavailErr ProfileUnavailableError
	require.ErrorAs(t, err, &unavailErr)
	assert.Contains(t, unavailErr.Cause.Error(), "repositories list must be non-empty")

	_, err = orgProfiles.Get("empty-permissions")
	require.Error(t, err)
	require.ErrorAs(t, err, &unavailErr)
	assert.Contains(t, unavailErr.Cause.Error(), "permissions list must be non-empty")

	_, err = orgProfiles.Get("both-empty")
	require.Error(t, err)
	require.ErrorAs(t, err, &unavailErr)
}

func TestCompile_DigestPreservation(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/valid_profile.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")

	assert.Equal(t, digest, profiles.digest, "digest should be preserved through compilation")
}

func TestCompile_LocationPreservation(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/valid_profile.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	location := "github://acme/profiles/main/profiles.yaml"
	profiles := compile(config, digest, location)

	stats := profiles.Stats()
	assert.Equal(t, location, stats.Location, "location should be preserved through compilation")
}

func TestCompile_PipelineDefaultsFallback(t *testing.T) {
	tests := []struct {
		name             string
		filename         string
		expectedDefaults []string
		description      string
	}{
		{
			name:             "configured defaults",
			filename:         "testdata/profile/profile_with_defaults.yaml",
			expectedDefaults: []string{"contents:read", "pull_requests:write"},
			description:      "should use configured defaults when present",
		},
		{
			name:             "fallback defaults",
			filename:         "testdata/profile/profile_with_match_rules.yaml",
			expectedDefaults: []string{"contents:read"},
			description:      "should fallback to contents:read when not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yamlContent, err := os.ReadFile(tt.filename)
			require.NoError(t, err)

			config, digest, err := parse(string(yamlContent))
			require.NoError(t, err)

			profiles := compile(config, digest, "local")

			defaultProfile, err := profiles.GetPipelineProfile("default")
			require.NoError(t, err)
			assert.Equal(t, tt.expectedDefaults, defaultProfile.Attrs.Permissions, tt.description)
		})
	}
}

func TestProfileMatching_ExactMatch_Success(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_match_rules.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")

	// Get the profile and test matching
	profile, err := profiles.GetOrgProfile("production-deploy")
	require.NoError(t, err)

	// Test with matching claims
	claims := mapClaimLookup{"pipeline_slug": "silk-prod"}
	result := profile.Match(claims)

	assert.True(t, result.Matched)
	assert.Equal(t, []ClaimMatch{{Claim: "pipeline_slug", Value: "silk-prod"}}, result.Matches)
	assert.Nil(t, result.Attempt)
	assert.NoError(t, result.Err)
}

func TestProfileMatching_ExactMatch_Failure(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_match_rules.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")

	// Get the profile and test matching
	profile, err := profiles.GetOrgProfile("production-deploy")
	require.NoError(t, err)

	// Test with non-matching claims
	claims := mapClaimLookup{"pipeline_slug": "cotton-prod"}
	result := profile.Match(claims)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	require.NotNil(t, result.Attempt)
	assert.Equal(t, "pipeline_slug", result.Attempt.Claim)
	assert.Equal(t, "silk-prod", result.Attempt.Pattern)
	assert.Equal(t, "cotton-prod", result.Attempt.ActualValue)
	assert.NoError(t, result.Err)
}

func TestProfileMatching_RegexMatch_Success(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_match_rules.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")

	// Get the profile and test matching
	profile, err := profiles.GetOrgProfile("staging-deploy")
	require.NoError(t, err)

	// Test with matching claims - should match pattern "(silk|cotton)-(staging|stg)"
	claims := mapClaimLookup{"pipeline_slug": "silk-staging"}
	result := profile.Match(claims)

	assert.True(t, result.Matched)
	assert.Equal(t, []ClaimMatch{{Claim: "pipeline_slug", Value: "silk-staging"}}, result.Matches)
	assert.Nil(t, result.Attempt)
	assert.NoError(t, result.Err)
}

func TestProfileMatching_RegexMatch_Failure(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_match_rules.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")

	// Get the profile and test matching
	profile, err := profiles.GetOrgProfile("staging-deploy")
	require.NoError(t, err)

	// Test with non-matching claims
	claims := mapClaimLookup{"pipeline_slug": "silk-production"}
	result := profile.Match(claims)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	require.NotNil(t, result.Attempt)
	assert.Equal(t, "pipeline_slug", result.Attempt.Claim)
	assert.Equal(t, "silk-production", result.Attempt.ActualValue)
	assert.NoError(t, result.Err)
}

func TestProfileMatching_MultipleRules_AllPass(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_match_rules.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")

	// Get the profile and test matching
	profile, err := profiles.GetOrgProfile("production-silk-only")
	require.NoError(t, err)

	// Test with all claims matching
	claims := mapClaimLookup{
		"pipeline_slug": "silk-prod",
		"build_branch":  "main",
	}
	result := profile.Match(claims)

	assert.True(t, result.Matched)
	assert.Len(t, result.Matches, 2)
	assert.Contains(t, result.Matches, ClaimMatch{Claim: "pipeline_slug", Value: "silk-prod"})
	assert.Contains(t, result.Matches, ClaimMatch{Claim: "build_branch", Value: "main"})
	assert.Nil(t, result.Attempt)
	assert.NoError(t, result.Err)
}

func TestProfileMatching_MultipleRules_OneFails(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_match_rules.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")

	// Get the profile and test matching
	profile, err := profiles.GetOrgProfile("production-silk-only")
	require.NoError(t, err)

	// Test with one claim not matching
	claims := mapClaimLookup{
		"pipeline_slug": "silk-prod",
		"build_branch":  "develop",
	}
	result := profile.Match(claims)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	require.NotNil(t, result.Attempt)
	assert.Equal(t, "build_branch", result.Attempt.Claim)
	assert.Equal(t, "main", result.Attempt.Pattern)
	assert.Equal(t, "develop", result.Attempt.ActualValue)
	assert.NoError(t, result.Err)
}

func TestProfileMatching_EmptyRules_AlwaysPasses(t *testing.T) {
	yamlContent, err := os.ReadFile("testdata/profile/profile_with_match_rules.yaml")
	require.NoError(t, err)

	config, digest, err := parse(string(yamlContent))
	require.NoError(t, err)

	profiles := compile(config, digest, "local")

	// Get the profile and test matching
	profile, err := profiles.GetOrgProfile("shared-utilities-read")
	require.NoError(t, err)

	// Test with empty claims - should still pass
	claims := mapClaimLookup{}
	result := profile.Match(claims)

	assert.True(t, result.Matched)
	assert.Empty(t, result.Matches)
	assert.Nil(t, result.Attempt)
	assert.NoError(t, result.Err)

	// Test with some claims - should also pass
	claims = mapClaimLookup{"pipeline_slug": "any-pipeline"}
	result = profile.Match(claims)

	assert.True(t, result.Matched)
	assert.Empty(t, result.Matches)
	assert.Nil(t, result.Attempt)
	assert.NoError(t, result.Err)
}

func TestCompilePipelineProfiles_ReservedNameRejection(t *testing.T) {
	profiles := []pipelineProfile{
		{
			Name:        "default",
			Permissions: []string{"contents:read"},
		},
		{
			Name:        "valid-profile",
			Permissions: []string{"contents:read", "pull_requests:write"},
		},
	}

	result := compilePipelineProfiles(profiles, []string{"contents:read"})

	// "default" should be invalid
	_, err := result.Get("default")
	require.NoError(t, err, "default profile should exist (created from defaults)")

	// "valid-profile" should be accessible
	validProfile, err := result.Get("valid-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"contents:read", "pull_requests:write"}, validProfile.Attrs.Permissions)

	// Check that the user-defined "default" was rejected
	assert.Equal(t, 1, result.InvalidProfileCount(), "user-defined 'default' should be marked invalid")
}

func TestCompilePipelineProfiles_EmptyMatchRulesPass(t *testing.T) {
	profiles := []pipelineProfile{
		{
			Name:        "open-profile",
			Match:       []matchRule{}, // Empty match rules
			Permissions: []string{"contents:read"},
		},
	}

	result := compilePipelineProfiles(profiles, []string{"contents:read"})

	profile, err := result.Get("open-profile")
	require.NoError(t, err)
	assert.Equal(t, []string{"contents:read"}, profile.Attrs.Permissions)

	// Empty match rules should match any claims
	claims := mapClaimLookup{"pipeline_slug": "any-pipeline"}
	matchResult := profile.Match(claims)
	assert.True(t, matchResult.Matched)
}

func TestCompilePipelineProfiles_EmptyPermissionsRejection(t *testing.T) {
	profiles := []pipelineProfile{
		{
			Name:        "no-permissions",
			Permissions: []string{}, // Empty permissions
		},
		{
			Name:        "valid-profile",
			Permissions: []string{"contents:read"},
		},
	}

	result := compilePipelineProfiles(profiles, []string{"contents:read"})

	// "no-permissions" should be invalid
	_, err := result.Get("no-permissions")
	require.Error(t, err)
	var unavailErr ProfileUnavailableError
	require.ErrorAs(t, err, &unavailErr)
	assert.Contains(t, unavailErr.Cause.Error(), "permissions list must be non-empty")

	// "valid-profile" should be accessible
	_, err = result.Get("valid-profile")
	require.NoError(t, err)
}

func TestCompilePipelineProfiles_DuplicateNames(t *testing.T) {
	profiles := []pipelineProfile{
		{
			Name:        "duplicate",
			Permissions: []string{"contents:read"},
		},
		{
			Name:        "duplicate",
			Permissions: []string{"pull_requests:write"},
		},
		{
			Name:        "unique",
			Permissions: []string{"issues:read"},
		},
	}

	result := compilePipelineProfiles(profiles, []string{"contents:read"})

	// With duplicate names, the last profile wins (second's attributes overwrite first)
	duplicateProfile, err := result.Get("duplicate")
	require.NoError(t, err)
	assert.Equal(t, []string{"pull_requests:write"}, duplicateProfile.Attrs.Permissions)

	// Second duplicate was rejected, verify invalid count
	assert.Equal(t, 1, result.InvalidProfileCount(), "second duplicate should be marked invalid")

	// "unique" should be accessible
	_, err = result.Get("unique")
	require.NoError(t, err)
}

func TestCompilePipelineProfiles_DefaultProfileCreation(t *testing.T) {
	tests := []struct {
		name                string
		profiles            []pipelineProfile
		defaultPermissions  []string
		expectedPermissions []string
	}{
		{
			name:                "default profile with custom permissions",
			profiles:            []pipelineProfile{},
			defaultPermissions:  []string{"contents:read", "pull_requests:write"},
			expectedPermissions: []string{"contents:read", "pull_requests:write"},
		},
		{
			name:                "default profile with single permission",
			profiles:            []pipelineProfile{},
			defaultPermissions:  []string{"contents:read"},
			expectedPermissions: []string{"contents:read"},
		},
		{
			name: "default profile exists alongside user profiles",
			profiles: []pipelineProfile{
				{
					Name:        "custom",
					Permissions: []string{"issues:read"},
				},
			},
			defaultPermissions:  []string{"contents:read"},
			expectedPermissions: []string{"contents:read"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compilePipelineProfiles(tt.profiles, tt.defaultPermissions)

			// "default" profile should exist
			defaultProfile, err := result.Get("default")
			require.NoError(t, err)
			assert.Equal(t, tt.expectedPermissions, defaultProfile.Attrs.Permissions)

			// Default profile should match any claims (empty match rules)
			claims := mapClaimLookup{"pipeline_slug": "any-pipeline"}
			matchResult := defaultProfile.Match(claims)
			assert.True(t, matchResult.Matched, "default profile should match any pipeline")
		})
	}
}

func TestCompilePipelineProfiles_WithMatchRules(t *testing.T) {
	profiles := []pipelineProfile{
		{
			Name: "specific-pipeline",
			Match: []matchRule{
				{Claim: "pipeline_slug", Value: "silk-prod"},
			},
			Permissions: []string{"contents:write"},
		},
	}

	result := compilePipelineProfiles(profiles, []string{"contents:read"})

	profile, err := result.Get("specific-pipeline")
	require.NoError(t, err)

	// Should match the specific pipeline
	matchingClaims := mapClaimLookup{"pipeline_slug": "silk-prod"}
	matchResult := profile.Match(matchingClaims)
	assert.True(t, matchResult.Matched)

	// Should not match a different pipeline
	nonMatchingClaims := mapClaimLookup{"pipeline_slug": "cotton-prod"}
	matchResult = profile.Match(nonMatchingClaims)
	assert.False(t, matchResult.Matched)
}
