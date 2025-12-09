package profile

import (
	"fmt"
	"regexp"
)

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

// RegexMatcher creates a matcher that performs RE2 regex pattern matching on a claim value.
// Patterns are automatically anchored to prevent substring matching.
// Returns an error if the pattern is invalid.
// Optimization: Purely literal patterns are automatically converted to ExactMatcher.
// Performance: O(n) RE2 linear time guarantee, or O(1) for literal patterns.
func RegexMatcher(matchClaim string, matchPattern string) (Matcher, error) {
	// 1. Validate user pattern compiles
	validatedRegex, err := regexp.Compile(matchPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	// 2. Optimization: if pattern is purely literal, use ExactMatcher
	prefix, complete := validatedRegex.LiteralPrefix()
	if complete {
		return ExactMatcher(matchClaim, prefix), nil
	}

	// 3. Wrap with non-capturing group and string anchors
	anchored := `\A(?:` + matchPattern + `)\z`

	// 4. Compile final pattern
	compiledRegex, err := regexp.Compile(anchored)
	if err != nil {
		return nil, fmt.Errorf("anchored pattern failed to compile: %w", err)
	}

	return func(claims ClaimValueLookup) ([]ClaimMatch, bool) {
		value, ok := claims.Lookup(matchClaim)
		if !ok || !compiledRegex.MatchString(value) {
			return nil, false
		}

		return []ClaimMatch{{
			Claim: matchClaim,
			Value: value,
		}}, true
	}, nil
}

// CompositeMatcher combines multiple matchers with AND logic.
// All matchers must succeed for the composite to succeed.
// Empty matcher list always succeeds (no conditions = always authorized).
// Single matcher optimization returns the matcher directly.
// Short-circuits on first failure.
func CompositeMatcher(matchers ...Matcher) Matcher {
	// Handle empty case: no match rules = always match
	if len(matchers) == 0 {
		return func(claims ClaimValueLookup) ([]ClaimMatch, bool) {
			return []ClaimMatch{}, true
		}
	}

	// Single matcher optimization
	if len(matchers) == 1 {
		return matchers[0]
	}

	// Multiple matchers: AND logic with short-circuit
	return func(claims ClaimValueLookup) ([]ClaimMatch, bool) {
		matches := make([]ClaimMatch, 0, len(matchers))

		for _, m := range matchers {
			mMatches, ok := m(claims)
			if !ok {
				// Short-circuit on first failure
				return nil, false
			}
			matches = append(matches, mMatches...)
		}

		return matches, true
	}
}
