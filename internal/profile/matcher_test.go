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
