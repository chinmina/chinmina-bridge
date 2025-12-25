package profile_test

import (
	"strings"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/stretchr/testify/assert"
)

// TestClaimMatch_TypeDefinition verifies ClaimMatch struct compiles with required fields.
func TestClaimMatch_TypeDefinition(t *testing.T) {
	match := profile.ClaimMatch{
		Claim: "pipeline_slug",
		Value: "my-pipeline",
	}

	expected := profile.ClaimMatch{
		Claim: "pipeline_slug",
		Value: "my-pipeline",
	}
	assert.Equal(t, expected, match)
}

// TestMatcher_TypeDefinition verifies Matcher function type compiles correctly.
func TestMatcher_TypeDefinition(t *testing.T) {
	// Create a simple matcher that always succeeds
	var matcher profile.Matcher = func(claims profile.ClaimValueLookup) profile.MatchResult {
		return profile.MatchResult{
			Matched: true,
			Matches: []profile.ClaimMatch{
				{Claim: "test", Value: "value"},
			},
		}
	}

	// Verify matcher can be called
	result := matcher(mockClaimLookup{})
	expected := profile.MatchResult{
		Matched: true,
		Matches: []profile.ClaimMatch{
			{Claim: "test", Value: "value"},
		},
	}
	assert.Equal(t, expected, result)
}

// TestClaimValueLookup_Interface_Success verifies ClaimValueLookup can find claims.
func TestClaimValueLookup_Interface_Success(t *testing.T) {
	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
			"build_branch":  "main",
		},
	}

	value, err := lookup.Lookup("pipeline_slug")
	assert.NoError(t, err)
	assert.Equal(t, "my-pipeline", value)
}

// TestClaimValueLookup_Interface_Missing verifies ClaimValueLookup errors on missing claims.
func TestClaimValueLookup_Interface_Missing(t *testing.T) {
	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
			"build_branch":  "main",
		},
	}

	value, err := lookup.Lookup("nonexistent")
	assert.ErrorIs(t, err, jwt.ErrClaimNotFound)
	assert.Equal(t, "", value)
}

// TestExactMatcher_Success tests exact match when claim exists with correct value.
func TestExactMatcher_Success(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
		},
	}

	result := matcher(lookup)

	expected := profile.MatchResult{
		Matched: true,
		Matches: []profile.ClaimMatch{
			{Claim: "pipeline_slug", Value: "my-pipeline"},
		},
	}
	assert.Equal(t, expected, result)
}

// TestExactMatcher_Failure tests no match scenarios.
func TestExactMatcher_Failure(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]string
		expected profile.MatchResult
	}{
		{
			name: "claim missing",
			claims: map[string]string{
				"build_branch": "main",
			},
			expected: profile.MatchResult{
				Matched: false,
				Attempt: &profile.MatchAttempt{
					Claim:       "pipeline_slug",
					Pattern:     "my-pipeline",
					ActualValue: "",
				},
			},
		},
		{
			name: "value mismatch",
			claims: map[string]string{
				"pipeline_slug": "other-pipeline",
			},
			expected: profile.MatchResult{
				Matched: false,
				Attempt: &profile.MatchAttempt{
					Claim:       "pipeline_slug",
					Pattern:     "my-pipeline",
					ActualValue: "other-pipeline",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
			lookup := mockClaimLookup{
				claims: tt.claims,
			}

			result := matcher(lookup)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRegexMatcher_ValidPattern tests regex matching with valid patterns.
func TestRegexMatcher_ValidPattern(t *testing.T) {
	matcher, err := profile.RegexMatcher("build_branch", "main|master")
	assert.NoError(t, err)

	tests := []struct {
		name     string
		value    string
		expected profile.MatchResult
	}{
		{
			name:  "matches main",
			value: "main",
			expected: profile.MatchResult{
				Matched: true,
				Matches: []profile.ClaimMatch{
					{Claim: "build_branch", Value: "main"},
				},
			},
		},
		{
			name:  "matches master",
			value: "master",
			expected: profile.MatchResult{
				Matched: true,
				Matches: []profile.ClaimMatch{
					{Claim: "build_branch", Value: "master"},
				},
			},
		},
		{
			name:  "no match develop",
			value: "develop",
			expected: profile.MatchResult{
				Matched: false,
				Attempt: &profile.MatchAttempt{
					Claim:       "build_branch",
					Pattern:     "main|master",
					ActualValue: "develop",
				},
			},
		},
		{
			name:  "no substring match",
			value: "not-main",
			expected: profile.MatchResult{
				Matched: false,
				Attempt: &profile.MatchAttempt{
					Claim:       "build_branch",
					Pattern:     "main|master",
					ActualValue: "not-main",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := mockClaimLookup{
				claims: map[string]string{
					"build_branch": tt.value,
				},
			}

			result := matcher(lookup)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRegexMatcher_InvalidPattern tests error handling for invalid regex.
func TestRegexMatcher_InvalidPattern(t *testing.T) {
	matcher, err := profile.RegexMatcher("build_branch", "[invalid")

	assert.Error(t, err)
	assert.Nil(t, matcher)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

// TestRegexMatcher_LiteralOptimization tests that literal patterns use ExactMatcher.
func TestRegexMatcher_LiteralOptimization(t *testing.T) {
	// Purely literal pattern should be optimized to ExactMatcher
	matcher, err := profile.RegexMatcher("pipeline_slug", "my-pipeline")
	assert.NoError(t, err)

	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
		},
	}

	result := matcher(lookup)

	expected := profile.MatchResult{
		Matched: true,
		Matches: []profile.ClaimMatch{
			{Claim: "pipeline_slug", Value: "my-pipeline"},
		},
	}
	assert.Equal(t, expected, result)
}

// TestRegexMatcher_AnchoringPreventsSubstring tests that patterns are anchored.
func TestRegexMatcher_AnchoringPreventsSubstring(t *testing.T) {
	// Pattern should match entire string, not substring
	matcher, err := profile.RegexMatcher("build_branch", "main")
	assert.NoError(t, err)

	lookup := mockClaimLookup{
		claims: map[string]string{
			"build_branch": "not-main-branch",
		},
	}

	result := matcher(lookup)

	expected := profile.MatchResult{
		Matched: false,
		Attempt: &profile.MatchAttempt{
			Claim:       "build_branch",
			Pattern:     "main",
			ActualValue: "not-main-branch",
		},
	}
	assert.Equal(t, expected, result)
}

// TestCompositeMatcher_Empty tests that empty matcher list always matches.
func TestCompositeMatcher_Empty(t *testing.T) {
	matcher := profile.CompositeMatcher()
	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
		},
	}

	result := matcher(lookup)

	expected := profile.MatchResult{
		Matched: true,
		Matches: []profile.ClaimMatch{},
	}
	assert.Equal(t, expected, result)
}

// TestCompositeMatcher_Single tests single matcher optimization.
func TestCompositeMatcher_Single(t *testing.T) {
	exactMatcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	composite := profile.CompositeMatcher(exactMatcher)

	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
		},
	}

	result := composite(lookup)

	expected := profile.MatchResult{
		Matched: true,
		Matches: []profile.ClaimMatch{
			{Claim: "pipeline_slug", Value: "my-pipeline"},
		},
	}
	assert.Equal(t, expected, result)
}

// TestCompositeMatcher_Multiple tests AND logic with all matchers succeeding.
func TestCompositeMatcher_Multiple(t *testing.T) {
	matcher1 := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	matcher2 := profile.ExactMatcher("build_branch", "main")

	composite := profile.CompositeMatcher(matcher1, matcher2)

	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
			"build_branch":  "main",
		},
	}

	result := composite(lookup)

	expected := profile.MatchResult{
		Matched: true,
		Matches: []profile.ClaimMatch{
			{Claim: "pipeline_slug", Value: "my-pipeline"},
			{Claim: "build_branch", Value: "main"},
		},
	}
	assert.Equal(t, expected, result)
}

// TestCompositeMatcher_ShortCircuit tests that evaluation stops on first failure.
func TestCompositeMatcher_ShortCircuit(t *testing.T) {
	matcher1 := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	matcher2 := profile.ExactMatcher("build_branch", "develop") // This will fail

	composite := profile.CompositeMatcher(matcher1, matcher2)

	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
			"build_branch":  "main", // doesn't match "develop"
		},
	}

	result := composite(lookup)

	expected := profile.MatchResult{
		Matched: false,
		Attempt: &profile.MatchAttempt{
			Claim:       "build_branch",
			Pattern:     "develop",
			ActualValue: "main",
		},
	}
	assert.Equal(t, expected, result)
}

// TestIsUnicodeControlOrWhitespace tests the Unicode validation function.
func TestIsUnicodeControlOrWhitespace(t *testing.T) {
	tests := []struct {
		name     string
		input    rune
		expected bool
	}{
		// Control characters
		{"null character", '\x00', true},
		{"tab", '\t', true},
		{"newline", '\n', true},
		{"carriage return", '\r', true},
		{"backspace", '\b', true},
		{"form feed", '\f', true},
		{"vertical tab", '\v', true},
		{"escape", '\x1b', true},
		{"delete", '\x7f', true},

		// Whitespace
		{"space", ' ', true},
		{"non-breaking space", '\u00a0', true},
		{"em space", '\u2003', true},

		// Regular characters (should be false)
		{"lowercase letter", 'a', false},
		{"uppercase letter", 'Z', false},
		{"digit", '5', false},
		{"hyphen", '-', false},
		{"underscore", '_', false},
		{"colon", ':', false},
		{"unicode letter", 'ü', false},
		{"emoji", '🎉', false},
		{"zero-width space", '\u200b', false}, // Not classified as whitespace by unicode.IsSpace
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := profile.IsUnicodeControlOrWhitespace(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsValidClaimPart tests the claim part validation function.
func TestIsValidClaimPart(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid claim parts
		{"simple alphanumeric", "deployment-queue", true},
		{"with hyphens", "my-pipeline-name", true},
		{"with underscores", "my_queue_name", true},
		{"with colons", "agent_tag:queue", true},
		{"with unicode", "queue-ümlaut", true},
		{"numeric", "12345", true},
		{"with dots", "v1.2.3", true},

		// Invalid claim parts
		{"with tab", "value\ttab", false},
		{"with newline", "value\nline", false},
		{"with space", "value with space", false},
		{"with carriage return", "value\r", false},
		{"with non-breaking space", "value\u00a0", false},
		{"with control char", "value\x1b", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := profile.IsValidClaimPart(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidatingLookup_ValidClaims tests validation passes for valid claim values.
func TestValidatingLookup_ValidClaims(t *testing.T) {
	tests := []struct {
		name       string
		claim      string
		claimValue string
	}{
		{"pipeline slug", "pipeline_slug", "my-pipeline"},
		{"build branch", "build_branch", "main"},
		{"agent tag", "agent_tag:queue", "deployment-queue"},
		{"with unicode", "build_branch", "feature-ümlaut"},
		{"with underscores", "pipeline_slug", "my_pipeline_name"},
		{"numeric", "build_number", "12345"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseLookup := mockClaimLookup{
				claims: map[string]string{
					tt.claim: tt.claimValue,
				},
			}
			lookup := profile.NewValidatingLookup(baseLookup)

			value, err := lookup.Lookup(tt.claim)
			assert.NoError(t, err)
			assert.Equal(t, tt.claimValue, value)
		})
	}
}

// TestValidatingLookup_InvalidCharacters tests validation rejects invalid characters in all claims.
func TestValidatingLookup_InvalidCharacters(t *testing.T) {
	tests := []struct {
		name       string
		claim      string
		claimValue string
		errorMsg   string
	}{
		{
			name:       "pipeline slug with tab",
			claim:      "pipeline_slug",
			claimValue: "my\tpipeline",
			errorMsg:   "invalid characters",
		},
		{
			name:       "build branch with newline",
			claim:      "build_branch",
			claimValue: "main\nline",
			errorMsg:   "invalid characters",
		},
		{
			name:       "agent tag with space",
			claim:      "agent_tag:queue",
			claimValue: "queue name",
			errorMsg:   "invalid characters",
		},
		{
			name:       "pipeline slug with non-breaking space",
			claim:      "pipeline_slug",
			claimValue: "my\u00a0pipeline",
			errorMsg:   "invalid characters",
		},
		{
			name:       "build branch with control character",
			claim:      "build_branch",
			claimValue: "feature\x1bname",
			errorMsg:   "invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseLookup := mockClaimLookup{
				claims: map[string]string{
					tt.claim: tt.claimValue,
				},
			}
			lookup := profile.NewValidatingLookup(baseLookup)

			value, err := lookup.Lookup(tt.claim)

			assert.Error(t, err)
			var validationErr profile.ClaimValidationError
			assert.ErrorAs(t, err, &validationErr)
			assert.Equal(t, tt.claim, validationErr.Claim)
			assert.Equal(t, tt.claimValue, validationErr.Value)
			assert.Contains(t, validationErr.Error(), tt.errorMsg)
			assert.Equal(t, "", value)
		})
	}
}

// TestValidatingLookup_LengthValidation tests validation enforces 256 character limit on all claims.
func TestValidatingLookup_LengthValidation(t *testing.T) {
	tests := []struct {
		name        string
		claim       string
		claimValue  string
		expectError bool
	}{
		{
			name:        "pipeline slug at max length",
			claim:       "pipeline_slug",
			claimValue:  strings.Repeat("a", 256),
			expectError: false,
		},
		{
			name:        "pipeline slug exceeds max length",
			claim:       "pipeline_slug",
			claimValue:  strings.Repeat("a", 257),
			expectError: true,
		},
		{
			name:        "build branch at max length",
			claim:       "build_branch",
			claimValue:  strings.Repeat("b", 256),
			expectError: false,
		},
		{
			name:        "build branch exceeds max length",
			claim:       "build_branch",
			claimValue:  strings.Repeat("b", 257),
			expectError: true,
		},
		{
			name:        "agent tag at max length",
			claim:       "agent_tag:queue",
			claimValue:  strings.Repeat("q", 256),
			expectError: false,
		},
		{
			name:        "agent tag exceeds max length",
			claim:       "agent_tag:queue",
			claimValue:  strings.Repeat("q", 257),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseLookup := mockClaimLookup{
				claims: map[string]string{
					tt.claim: tt.claimValue,
				},
			}
			lookup := profile.NewValidatingLookup(baseLookup)

			value, err := lookup.Lookup(tt.claim)

			if tt.expectError {
				assert.Error(t, err)
				var validationErr profile.ClaimValidationError
				assert.ErrorAs(t, err, &validationErr)
				assert.Equal(t, tt.claim, validationErr.Claim)
				assert.Contains(t, validationErr.Error(), "exceeds maximum length")
				assert.Equal(t, "", value)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.claimValue, value)
			}
		})
	}
}

// TestValidatingLookup_ErrorPropagation tests that errors from the base lookup are propagated.
func TestValidatingLookup_ErrorPropagation(t *testing.T) {
	baseLookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
		},
	}
	lookup := profile.NewValidatingLookup(baseLookup)

	// Missing claim should propagate ErrClaimNotFound
	value, err := lookup.Lookup("nonexistent")
	assert.ErrorIs(t, err, jwt.ErrClaimNotFound)
	assert.Equal(t, "", value)
}

// TestMatcher_ValidationError tests that matchers propagate validation errors.
func TestMatcher_ValidationError(t *testing.T) {
	tests := []struct {
		name          string
		matcher       func() (profile.Matcher, error)
		claims        map[string]string
		expectedClaim string
	}{
		{
			name: "exact matcher with invalid claim value",
			matcher: func() (profile.Matcher, error) {
				return profile.ExactMatcher("pipeline_slug", "my-pipeline"), nil
			},
			claims: map[string]string{
				"pipeline_slug": "my\tpipeline",
			},
			expectedClaim: "pipeline_slug",
		},
		{
			name: "regex matcher with invalid claim value",
			matcher: func() (profile.Matcher, error) {
				return profile.RegexMatcher("build_branch", "main|master")
			},
			claims: map[string]string{
				"build_branch": "main\nline",
			},
			expectedClaim: "build_branch",
		},
		{
			name: "composite matcher with validation error in second matcher",
			matcher: func() (profile.Matcher, error) {
				matcher1 := profile.ExactMatcher("pipeline_slug", "my-pipeline")
				matcher2 := profile.ExactMatcher("build_branch", "main")
				return profile.CompositeMatcher(matcher1, matcher2), nil
			},
			claims: map[string]string{
				"pipeline_slug": "my-pipeline",
				"build_branch":  "invalid space",
			},
			expectedClaim: "build_branch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := tt.matcher()
			assert.NoError(t, err)

			baseLookup := mockClaimLookup{
				claims: tt.claims,
			}
			lookup := profile.NewValidatingLookup(baseLookup)

			result := matcher(lookup)

			assert.False(t, result.Matched)
			assert.Nil(t, result.Attempt)
			assert.Error(t, result.Err)
			var validationErr profile.ClaimValidationError
			assert.ErrorAs(t, result.Err, &validationErr)
			assert.Equal(t, tt.expectedClaim, validationErr.Claim)
		})
	}
}

// mockClaimLookup implements ClaimValueLookup for testing.
type mockClaimLookup struct {
	claims map[string]string
}

func (m mockClaimLookup) Lookup(claim string) (string, error) {
	if m.claims == nil {
		return "", jwt.ErrClaimNotFound
	}
	value, found := m.claims[claim]
	if !found {
		return "", jwt.ErrClaimNotFound
	}
	return value, nil
}
