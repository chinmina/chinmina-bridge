package profile

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
)

// ClaimValueLookup provides zero-allocation interface for claim value retrieval.
// Instead of passing claims as a map, this interface allows transparent handling
// of standard claims and agent tags without allocations.
type ClaimValueLookup interface {
	// Lookup retrieves the value for a claim.
	// Returns (value, nil) if the claim exists and has a value.
	// Returns ("", jwt.ErrClaimNotFound) if the claim is absent or empty (for optional claims).
	// Returns ("", ClaimValidationError) if the claim value fails validation.
	Lookup(claim string) (value string, err error)
}

// ClaimMatch records which claim matched and its value for audit logging.
// This provides traceability showing exactly which claims were evaluated
// when authorizing access to a profile.
type ClaimMatch struct {
	Claim string // The claim name that was matched (e.g., "pipeline_slug", "agent_tag:queue")
	Value string // The actual value that satisfied the match condition
}

// ValidatingLookup wraps a ClaimValueLookup to add validation of claim values.
// This is applied at the vendor layer to validate claims lazily: only claims
// actually used in matchers are validated.
type ValidatingLookup struct {
	lookup ClaimValueLookup
}

// NewValidatingLookup creates a new ValidatingLookup wrapper around the provided lookup.
func NewValidatingLookup(lookup ClaimValueLookup) *ValidatingLookup {
	return &ValidatingLookup{lookup: lookup}
}

// Lookup retrieves and validates a claim value.
// Returns (value, nil) if the claim exists, has a value, and passes validation.
// Returns ("", jwt.ErrClaimNotFound) if the claim is absent.
// Returns ("", ClaimValidationError) if the claim value fails validation.
func (v *ValidatingLookup) Lookup(claim string) (string, error) {
	value, err := v.lookup.Lookup(claim)
	if err != nil {
		return "", err
	}

	// Agent tag validation: disallow control characters and enforce reasonable length
	if len(value) > 256 {
		return "", ClaimValidationError{
			Claim: claim,
			Value: value,
			Err:   fmt.Errorf("claim value exceeds maximum length of 256 characters"),
		}
	}

	if !IsValidClaimPart(value) {
		return "", ClaimValidationError{
			Claim: claim,
			Value: value,
			Err:   fmt.Errorf("claim value contains invalid characters"),
		}
	}

	return value, nil
}

// IsValidClaimPart checks if a claim part (name or value) is valid. Disallows
// control characters and whitespace, as these can cause security issues with
// claim processing.
func IsValidClaimPart(c string) bool {
	return !strings.ContainsFunc(c, IsUnicodeControlOrWhitespace)
}

func IsUnicodeControlOrWhitespace(r rune) bool {
	return unicode.IsControl(r) || unicode.IsSpace(r)
}

// Matcher evaluates whether claims satisfy match conditions.
// Returns matched claims for audit logging and an error indicating failure.
// Multiple ClaimMatch entries may be returned when composite matchers combine multiple conditions.
// Returns (matches, nil) on success, (nil, ErrNoMatch) when conditions aren't met,
// or (nil, error) for validation or other errors.
type Matcher func(claims ClaimValueLookup) (matches []ClaimMatch, err error)

// ExactMatcher creates a matcher that performs exact string comparison on a claim value.
// Returns a successful match only when the claim exists and exactly equals the expected value.
// Performance: O(1) string comparison.
func ExactMatcher(matchClaim string, matchValue string) Matcher {
	return func(claims ClaimValueLookup) ([]ClaimMatch, error) {
		value, err := claims.Lookup(matchClaim)
		if err != nil {
			// Distinguish between not found (no match) and validation error
			if err == jwt.ErrClaimNotFound {
				return nil, ErrNoMatch
			}
			return nil, err
		}

		if value != matchValue {
			return nil, ErrNoMatch
		}

		return []ClaimMatch{{
			Claim: matchClaim,
			Value: value,
		}}, nil
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

	return func(claims ClaimValueLookup) ([]ClaimMatch, error) {
		value, err := claims.Lookup(matchClaim)
		if err != nil {
			// Distinguish between not found (no match) and validation error
			if err == jwt.ErrClaimNotFound {
				return nil, ErrNoMatch
			}
			return nil, err
		}

		if !compiledRegex.MatchString(value) {
			return nil, ErrNoMatch
		}

		return []ClaimMatch{{
			Claim: matchClaim,
			Value: value,
		}}, nil
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
		return func(claims ClaimValueLookup) ([]ClaimMatch, error) {
			return []ClaimMatch{}, nil
		}
	}

	// Single matcher optimization
	if len(matchers) == 1 {
		return matchers[0]
	}

	// Multiple matchers: AND logic with short-circuit
	return func(claims ClaimValueLookup) ([]ClaimMatch, error) {
		matches := make([]ClaimMatch, 0, len(matchers))

		for _, m := range matchers {
			mMatches, err := m(claims)
			if err != nil {
				// Short-circuit on first failure
				return nil, err
			}
			matches = append(matches, mMatches...)
		}

		return matches, nil
	}
}
