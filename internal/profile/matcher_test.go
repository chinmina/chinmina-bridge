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

	assert.Equal(t, "pipeline_slug", match.Claim)
	assert.Equal(t, "my-pipeline", match.Value)
}

// TestMatcher_TypeDefinition verifies Matcher function type compiles correctly.
func TestMatcher_TypeDefinition(t *testing.T) {
	// Create a simple matcher that always succeeds
	var matcher profile.Matcher = func(claims profile.ClaimValueLookup) ([]profile.ClaimMatch, error) {
		return []profile.ClaimMatch{
			{Claim: "test", Value: "value"},
		}, nil
	}

	// Verify matcher can be called
	matches, err := matcher(mockClaimLookup{})
	assert.NoError(t, err)
	assert.Len(t, matches, 1)
	assert.Equal(t, "test", matches[0].Claim)
	assert.Equal(t, "value", matches[0].Value)
}

// TestClaimValueLookup_Interface verifies ClaimValueLookup interface can be implemented.
func TestClaimValueLookup_Interface(t *testing.T) {
	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
			"build_branch":  "main",
		},
	}

	// Test found claim
	value, err := lookup.Lookup("pipeline_slug")
	assert.NoError(t, err)
	assert.Equal(t, "my-pipeline", value)

	// Test missing claim
	value, err = lookup.Lookup("nonexistent")
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

	matches, err := matcher(lookup)

	expected := []profile.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
	}
	assert.NoError(t, err)
	assert.Equal(t, expected, matches)
}

// TestExactMatcher_ClaimMissing tests no match when claim is absent.
func TestExactMatcher_ClaimMissing(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	lookup := mockClaimLookup{
		claims: map[string]string{
			"build_branch": "main",
		},
	}

	matches, err := matcher(lookup)

	assert.ErrorIs(t, err, profile.ErrNoMatch)
	assert.Nil(t, matches)
}

// TestExactMatcher_ValueMismatch tests no match when claim exists with different value.
func TestExactMatcher_ValueMismatch(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "other-pipeline",
		},
	}

	matches, err := matcher(lookup)

	assert.ErrorIs(t, err, profile.ErrNoMatch)
	assert.Nil(t, matches)
}

// TestRegexMatcher_ValidPattern tests regex matching with valid patterns.
func TestRegexMatcher_ValidPattern(t *testing.T) {
	matcher, err := profile.RegexMatcher("build_branch", "main|master")
	assert.NoError(t, err)

	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"matches main", "main", true},
		{"matches master", "master", true},
		{"no match develop", "develop", false},
		{"no substring match", "not-main", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := mockClaimLookup{
				claims: map[string]string{
					"build_branch": tt.value,
				},
			}

			matches, err := matcher(lookup)

			if tt.expected {
				assert.NoError(t, err)
				assert.Len(t, matches, 1)
				assert.Equal(t, "build_branch", matches[0].Claim)
				assert.Equal(t, tt.value, matches[0].Value)
			} else {
				assert.ErrorIs(t, err, profile.ErrNoMatch)
				assert.Nil(t, matches)
			}
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

	matches, err := matcher(lookup)

	expected := []profile.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
	}
	assert.NoError(t, err)
	assert.Equal(t, expected, matches)
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

	matches, err := matcher(lookup)

	// Should not match because pattern is anchored
	assert.ErrorIs(t, err, profile.ErrNoMatch)
	assert.Nil(t, matches)
}

// TestCompositeMatcher_Empty tests that empty matcher list always matches.
func TestCompositeMatcher_Empty(t *testing.T) {
	matcher := profile.CompositeMatcher()
	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
		},
	}

	matches, err := matcher(lookup)

	assert.NoError(t, err)
	assert.Equal(t, []profile.ClaimMatch{}, matches)
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

	matches, err := composite(lookup)

	expected := []profile.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
	}
	assert.NoError(t, err)
	assert.Equal(t, expected, matches)
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

	matches, err := composite(lookup)

	expected := []profile.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
		{Claim: "build_branch", Value: "main"},
	}
	assert.NoError(t, err)
	assert.Equal(t, expected, matches)
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

	matches, err := composite(lookup)

	// Should fail because second matcher doesn't match
	assert.ErrorIs(t, err, profile.ErrNoMatch)
	assert.Nil(t, matches)
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

// TestExactMatcher_ValidationError tests that exact matcher propagates validation errors.
func TestExactMatcher_ValidationError(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")

	// Create lookup with invalid claim value (contains tab)
	baseLookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my\tpipeline",
		},
	}
	lookup := profile.NewValidatingLookup(baseLookup)

	matches, err := matcher(lookup)

	assert.Error(t, err)
	var validationErr profile.ClaimValidationError
	assert.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "pipeline_slug", validationErr.Claim)
	assert.Nil(t, matches)
}

// TestRegexMatcher_ValidationError tests that regex matcher propagates validation errors.
func TestRegexMatcher_ValidationError(t *testing.T) {
	matcher, err := profile.RegexMatcher("build_branch", "main|master")
	assert.NoError(t, err)

	// Create lookup with invalid claim value (contains newline)
	baseLookup := mockClaimLookup{
		claims: map[string]string{
			"build_branch": "main\nline",
		},
	}
	lookup := profile.NewValidatingLookup(baseLookup)

	matches, err := matcher(lookup)

	assert.Error(t, err)
	var validationErr profile.ClaimValidationError
	assert.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "build_branch", validationErr.Claim)
	assert.Nil(t, matches)
}

// TestCompositeMatcher_ValidationError tests that composite matcher propagates validation errors.
func TestCompositeMatcher_ValidationError(t *testing.T) {
	matcher1 := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	matcher2 := profile.ExactMatcher("build_branch", "main")

	composite := profile.CompositeMatcher(matcher1, matcher2)

	// First matcher succeeds, second encounters validation error
	baseLookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
			"build_branch":  "invalid space",
		},
	}
	lookup := profile.NewValidatingLookup(baseLookup)

	matches, err := composite(lookup)

	assert.Error(t, err)
	var validationErr profile.ClaimValidationError
	assert.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "build_branch", validationErr.Claim)
	assert.Nil(t, matches)
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
