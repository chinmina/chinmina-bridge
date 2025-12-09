package profile

// ClaimValueLookup provides zero-allocation interface for claim value retrieval.
// Instead of passing claims as a map, this interface allows transparent handling
// of standard claims and agent tags without allocations.
type ClaimValueLookup interface {
	// Lookup retrieves the value for a claim.
	// Returns (value, true) if the claim exists and has a value.
	// Returns ("", false) if the claim is absent or empty (for optional claims).
	Lookup(claim string) (value string, found bool)
}

// ClaimMatch records which claim matched and its value for audit logging.
// This provides traceability showing exactly which claims were evaluated
// when authorizing access to a profile.
type ClaimMatch struct {
	Claim string // The claim name that was matched (e.g., "pipeline_slug", "agent_tag:queue")
	Value string // The actual value that satisfied the match condition
}

// Matcher evaluates whether claims satisfy match conditions.
// Returns matched claims for audit logging and a boolean indicating success.
// Multiple ClaimMatch entries may be returned when composite matchers combine multiple conditions.
type Matcher func(claims ClaimValueLookup) (matches []ClaimMatch, ok bool)

// ExactMatcher creates a matcher that performs exact string comparison on a claim value.
// Returns a successful match only when the claim exists and exactly equals the expected value.
// Performance: O(1) string comparison.
func ExactMatcher(matchClaim string, matchValue string) Matcher {
	return func(claims ClaimValueLookup) ([]ClaimMatch, bool) {
		value, ok := claims.Lookup(matchClaim)
		if !ok || value != matchValue {
			return nil, false
		}

		return []ClaimMatch{{
			Claim: matchClaim,
			Value: value,
		}}, true
	}
}
