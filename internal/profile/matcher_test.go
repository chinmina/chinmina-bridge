package profile

import (
	"errors"
	"strings"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapClaimLookup implements ClaimValueLookup for testing
type mapClaimLookup map[string]string

func (m mapClaimLookup) Lookup(claim string) (string, error) {
	value, ok := m[claim]
	if !ok || value == "" {
		return "", jwt.ErrClaimNotFound
	}
	return value, nil
}

func TestExactMatcher_Success(t *testing.T) {
	claims := mapClaimLookup{"pipeline_slug": "silk-prod"}
	matcher := ExactMatcher("pipeline_slug", "silk-prod")

	result := matcher(claims)

	assert.True(t, result.Matched)
	assert.Equal(t, []ClaimMatch{
		{Claim: "pipeline_slug", Value: "silk-prod"},
	}, result.Matches)
	assert.Nil(t, result.Attempt)
	assert.NoError(t, result.Err)
}

func TestExactMatcher_ClaimMissing(t *testing.T) {
	claims := mapClaimLookup{}
	matcher := ExactMatcher("pipeline_slug", "silk-prod")

	result := matcher(claims)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	require.NotNil(t, result.Attempt)
	assert.Equal(t, MatchAttempt{
		Claim:       "pipeline_slug",
		Pattern:     "silk-prod",
		ActualValue: "",
	}, *result.Attempt)
	assert.NoError(t, result.Err)
}

func TestExactMatcher_ValueMismatch(t *testing.T) {
	claims := mapClaimLookup{"pipeline_slug": "cotton-prod"}
	matcher := ExactMatcher("pipeline_slug", "silk-prod")

	result := matcher(claims)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	require.NotNil(t, result.Attempt)
	assert.Equal(t, MatchAttempt{
		Claim:       "pipeline_slug",
		Pattern:     "silk-prod",
		ActualValue: "cotton-prod",
	}, *result.Attempt)
	assert.NoError(t, result.Err)
}

func TestRegexMatcher_Alternation(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		matched bool
	}{
		{
			name:    "matches first option",
			value:   "main",
			matched: true,
		},
		{
			name:    "matches second option",
			value:   "master",
			matched: true,
		},
		{
			name:    "no match for other value",
			value:   "develop",
			matched: false,
		},
	}

	matcher, err := RegexMatcher("build_branch", "main|master")
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := mapClaimLookup{"build_branch": tt.value}
			result := matcher(claims)
			assert.Equal(t, tt.matched, result.Matched)
		})
	}
}

func TestRegexMatcher_Anchoring(t *testing.T) {
	matcher, err := RegexMatcher("build_branch", "main")
	require.NoError(t, err)

	tests := []struct {
		name    string
		value   string
		matched bool
	}{
		{
			name:    "exact match",
			value:   "main",
			matched: true,
		},
		{
			name:    "substring doesn't match",
			value:   "not-main-branch",
			matched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := mapClaimLookup{"build_branch": tt.value}
			result := matcher(claims)
			assert.Equal(t, tt.matched, result.Matched)
		})
	}
}

func TestRegexMatcher_InvalidPattern(t *testing.T) {
	matcher, err := RegexMatcher("pipeline_slug", "[invalid")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
	assert.Nil(t, matcher)
}

func TestRegexMatcher_LiteralOptimization(t *testing.T) {
	// Purely literal patterns should be optimized to ExactMatcher
	matcher, err := RegexMatcher("pipeline_slug", "silk-prod")
	require.NoError(t, err)

	claims := mapClaimLookup{"pipeline_slug": "silk-prod"}
	result := matcher(claims)

	assert.True(t, result.Matched)
	assert.Equal(t, []ClaimMatch{
		{Claim: "pipeline_slug", Value: "silk-prod"},
	}, result.Matches)
}

func TestCompositeMatcher_EmptyList(t *testing.T) {
	matcher := CompositeMatcher()
	claims := mapClaimLookup{}

	result := matcher(claims)

	assert.True(t, result.Matched)
	assert.Empty(t, result.Matches)
}

func TestCompositeMatcher_SingleMatcher(t *testing.T) {
	singleMatcher := ExactMatcher("pipeline_slug", "silk-prod")
	composite := CompositeMatcher(singleMatcher)

	claims := mapClaimLookup{"pipeline_slug": "silk-prod"}
	result := composite(claims)

	assert.True(t, result.Matched)
	assert.Equal(t, []ClaimMatch{
		{Claim: "pipeline_slug", Value: "silk-prod"},
	}, result.Matches)
}

func TestCompositeMatcher_MultipleMatchers_AllSucceed(t *testing.T) {
	matcher1 := ExactMatcher("pipeline_slug", "silk-prod")
	matcher2 := ExactMatcher("build_branch", "main")

	composite := CompositeMatcher(matcher1, matcher2)
	claims := mapClaimLookup{
		"pipeline_slug": "silk-prod",
		"build_branch":  "main",
	}

	result := composite(claims)

	assert.True(t, result.Matched)
	assert.Equal(t, []ClaimMatch{
		{Claim: "pipeline_slug", Value: "silk-prod"},
		{Claim: "build_branch", Value: "main"},
	}, result.Matches)
}

func TestCompositeMatcher_MultipleMatchers_OneFails(t *testing.T) {
	matcher1 := ExactMatcher("pipeline_slug", "silk-prod")
	matcher2 := ExactMatcher("build_branch", "main")

	composite := CompositeMatcher(matcher1, matcher2)
	claims := mapClaimLookup{
		"pipeline_slug": "silk-prod",
		"build_branch":  "develop",
	}

	result := composite(claims)

	assert.False(t, result.Matched)
	require.NotNil(t, result.Attempt)
	assert.Equal(t, "build_branch", result.Attempt.Claim)
	assert.Equal(t, "main", result.Attempt.Pattern)
	assert.Equal(t, "develop", result.Attempt.ActualValue)
}

func TestCompositeMatcher_ShortCircuit(t *testing.T) {
	matcher1 := ExactMatcher("pipeline_slug", "silk-prod")
	matcher2 := ExactMatcher("build_branch", "main")

	composite := CompositeMatcher(matcher1, matcher2)

	// First matcher fails, so second shouldn't be evaluated
	claims := mapClaimLookup{
		"pipeline_slug": "wrong-value",
		// build_branch intentionally missing
	}

	result := composite(claims)

	assert.False(t, result.Matched)
	require.NotNil(t, result.Attempt)
	// Should fail on first matcher, not second
	assert.Equal(t, "pipeline_slug", result.Attempt.Claim)
}

func TestIsUnicodeControlOrWhitespace(t *testing.T) {
	tests := []struct {
		name     string
		char     rune
		expected bool
	}{
		// Control characters
		{name: "null", char: '\x00', expected: true},
		{name: "tab", char: '\t', expected: true},
		{name: "newline", char: '\n', expected: true},
		{name: "carriage return", char: '\r', expected: true},
		{name: "backspace", char: '\b', expected: true},
		{name: "form feed", char: '\f', expected: true},
		{name: "vertical tab", char: '\v', expected: true},
		{name: "escape", char: '\x1b', expected: true},
		{name: "delete", char: '\x7f', expected: true},

		// Whitespace
		{name: "space", char: ' ', expected: true},
		{name: "non-breaking space", char: '\u00a0', expected: true},
		{name: "em space", char: '\u2003', expected: true},

		// Regular characters (should return false)
		{name: "letter a", char: 'a', expected: false},
		{name: "letter Z", char: 'Z', expected: false},
		{name: "digit 0", char: '0', expected: false},
		{name: "digit 9", char: '9', expected: false},
		{name: "hyphen", char: '-', expected: false},
		{name: "underscore", char: '_', expected: false},
		{name: "colon", char: ':', expected: false},
		{name: "unicode letter", char: 'é', expected: false},
		{name: "emoji", char: '🎉', expected: false},

		// Zero-width space is NOT classified as whitespace by unicode.IsSpace
		{name: "zero-width space", char: '\u200b', expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsUnicodeControlOrWhitespace(tt.char)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidClaimPart(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid inputs
		{name: "simple pipeline slug", input: "silk-prod", expected: true},
		{name: "build branch", input: "main", expected: true},
		{name: "agent tag", input: "agent_tag:environment", expected: true},
		{name: "unicode characters", input: "naïve", expected: true},
		{name: "underscores", input: "test_value", expected: true},
		{name: "numeric", input: "12345", expected: true},
		{name: "dots", input: "v1.2.3", expected: true},

		// Invalid inputs (contain control or whitespace)
		{name: "contains tab", input: "test\tvalue", expected: false},
		{name: "contains newline", input: "test\nvalue", expected: false},
		{name: "contains space", input: "test value", expected: false},
		{name: "contains carriage return", input: "test\rvalue", expected: false},
		{name: "contains non-breaking space", input: "test\u00a0value", expected: false},
		{name: "contains control character", input: "test\x00value", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidClaimPart(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidatingLookup_ValidClaims(t *testing.T) {
	tests := []struct {
		name  string
		claim string
		value string
	}{
		{name: "simple pipeline slug", claim: "pipeline_slug", value: "silk-prod"},
		{name: "build branch", claim: "build_branch", value: "main"},
		{name: "agent tag", claim: "agent_tag:environment", value: "production"},
		{name: "unicode characters", claim: "pipeline_slug", value: "naïve"},
		{name: "underscores", claim: "test_claim", value: "test_value"},
		{name: "numeric values", claim: "build_number", value: "12345"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseLookup := mapClaimLookup{tt.claim: tt.value}
			validating := NewValidatingLookup(baseLookup)

			value, err := validating.Lookup(tt.claim)
			require.NoError(t, err)
			assert.Equal(t, tt.value, value)
		})
	}
}

func TestValidatingLookup_InvalidCharacters(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "contains tab", value: "test\tvalue"},
		{name: "contains newline", value: "test\nvalue"},
		{name: "contains space", value: "test value"},
		{name: "contains non-breaking space", value: "test\u00a0value"},
		{name: "contains control character", value: "test\x00value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseLookup := mapClaimLookup{"test_claim": tt.value}
			validating := NewValidatingLookup(baseLookup)

			value, err := validating.Lookup("test_claim")
			require.Error(t, err)
			assert.Empty(t, value)

			var valErr ClaimValidationError
			require.ErrorAs(t, err, &valErr)
			assert.Equal(t, "test_claim", valErr.Claim)
			assert.Equal(t, tt.value, valErr.Value)
			assert.Contains(t, valErr.Err.Error(), "invalid characters")
		})
	}
}

func TestValidatingLookup_LengthValidation(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		shouldErr bool
	}{
		{name: "256 characters passes", length: 256, shouldErr: false},
		{name: "257 characters fails", length: 257, shouldErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a string of exactly tt.length characters
			value := strings.Repeat("a", tt.length)

			baseLookup := mapClaimLookup{"test_claim": value}
			validating := NewValidatingLookup(baseLookup)

			result, err := validating.Lookup("test_claim")

			if tt.shouldErr {
				require.Error(t, err)
				var valErr ClaimValidationError
				require.ErrorAs(t, err, &valErr)
				assert.Contains(t, valErr.Err.Error(), "exceeds maximum length")
			} else {
				require.NoError(t, err)
				assert.Equal(t, value, result)
			}
		})
	}
}

func TestValidatingLookup_ErrClaimNotFoundPropagation(t *testing.T) {
	baseLookup := mapClaimLookup{}
	validating := NewValidatingLookup(baseLookup)

	value, err := validating.Lookup("missing_claim")
	assert.Empty(t, value)
	assert.ErrorIs(t, err, jwt.ErrClaimNotFound)
}

func TestMatcherValidationErrorPropagation_ExactMatcher(t *testing.T) {
	// Create a validating lookup that will fail validation
	baseLookup := mapClaimLookup{"pipeline_slug": "test\tvalue"}
	validating := NewValidatingLookup(baseLookup)

	matcher := ExactMatcher("pipeline_slug", "test\tvalue")
	result := matcher(validating)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	assert.Nil(t, result.Attempt)
	require.Error(t, result.Err)

	var valErr ClaimValidationError
	require.ErrorAs(t, result.Err, &valErr)
}

func TestMatcherValidationErrorPropagation_RegexMatcher(t *testing.T) {
	baseLookup := mapClaimLookup{"pipeline_slug": "test\nvalue"}
	validating := NewValidatingLookup(baseLookup)

	matcher, err := RegexMatcher("pipeline_slug", ".*")
	require.NoError(t, err)

	result := matcher(validating)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	assert.Nil(t, result.Attempt)
	require.Error(t, result.Err)

	var valErr ClaimValidationError
	require.ErrorAs(t, result.Err, &valErr)
}

func TestMatcherValidationErrorPropagation_CompositeMatcher(t *testing.T) {
	matcher1 := ExactMatcher("pipeline_slug", "silk-prod")
	matcher2 := ExactMatcher("build_branch", "main")
	composite := CompositeMatcher(matcher1, matcher2)

	// Second matcher will encounter validation error
	baseLookup := mapClaimLookup{
		"pipeline_slug": "silk-prod",
		"build_branch":  "test\tvalue",
	}
	validating := NewValidatingLookup(baseLookup)

	result := composite(validating)

	assert.False(t, result.Matched)
	assert.Empty(t, result.Matches)
	assert.Nil(t, result.Attempt)
	require.Error(t, result.Err)

	var valErr ClaimValidationError
	require.ErrorAs(t, result.Err, &valErr)
	assert.Equal(t, "build_branch", valErr.Claim)
}

// mockLookupWithError implements ClaimValueLookup that returns a specific error
type mockLookupWithError struct {
	claim string
	err   error
}

func (m mockLookupWithError) Lookup(claim string) (string, error) {
	if claim == m.claim {
		return "", m.err
	}
	return "", jwt.ErrClaimNotFound
}

func TestExactMatcher_ValidationError(t *testing.T) {
	customErr := errors.New("custom validation error")
	lookup := mockLookupWithError{claim: "test_claim", err: customErr}
	matcher := ExactMatcher("test_claim", "expected")

	result := matcher(lookup)

	assert.False(t, result.Matched)
	assert.Nil(t, result.Attempt)
	assert.Equal(t, customErr, result.Err)
}
