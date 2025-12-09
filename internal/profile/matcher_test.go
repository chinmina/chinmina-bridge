package profile_test

import (
	"testing"

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
	var matcher profile.Matcher = func(claims profile.ClaimValueLookup) ([]profile.ClaimMatch, bool) {
		return []profile.ClaimMatch{
			{Claim: "test", Value: "value"},
		}, true
	}

	// Verify matcher can be called
	matches, ok := matcher(mockClaimLookup{})
	assert.True(t, ok)
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
	value, found := lookup.Lookup("pipeline_slug")
	assert.True(t, found)
	assert.Equal(t, "my-pipeline", value)

	// Test missing claim
	value, found = lookup.Lookup("nonexistent")
	assert.False(t, found)
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

	matches, ok := matcher(lookup)

	expected := []profile.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
	}
	assert.True(t, ok)
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

	matches, ok := matcher(lookup)

	assert.False(t, ok)
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

	matches, ok := matcher(lookup)

	assert.False(t, ok)
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

			matches, ok := matcher(lookup)

			assert.Equal(t, tt.expected, ok)
			if tt.expected {
				assert.Len(t, matches, 1)
				assert.Equal(t, "build_branch", matches[0].Claim)
				assert.Equal(t, tt.value, matches[0].Value)
			} else {
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

	matches, ok := matcher(lookup)

	expected := []profile.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
	}
	assert.True(t, ok)
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

	matches, ok := matcher(lookup)

	// Should not match because pattern is anchored
	assert.False(t, ok)
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

	matches, ok := matcher(lookup)

	assert.True(t, ok)
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

	matches, ok := composite(lookup)

	expected := []profile.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
	}
	assert.True(t, ok)
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

	matches, ok := composite(lookup)

	expected := []profile.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
		{Claim: "build_branch", Value: "main"},
	}
	assert.True(t, ok)
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

	matches, ok := composite(lookup)

	// Should fail because second matcher doesn't match
	assert.False(t, ok)
	assert.Nil(t, matches)
}

// mockClaimLookup implements ClaimValueLookup for testing.
type mockClaimLookup struct {
	claims map[string]string
}

func (m mockClaimLookup) Lookup(claim string) (string, bool) {
	if m.claims == nil {
		return "", false
	}
	value, found := m.claims[claim]
	return value, found
}
