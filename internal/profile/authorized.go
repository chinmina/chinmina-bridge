package profile

import "slices"

// OrganizationProfileAttr contains the attributes for an organization profile.
// Slice fields are expected to be treated as immutable after construction.
// Callers should not modify slice contents after passing to NewAuthorizedProfile or NewProfileStoreOf.
type OrganizationProfileAttr struct {
	Repositories []string
	Permissions  []string
}

// HasRepository checks if the given repository is included in the profile's
// repositories. Supports wildcard "*" to match any repository.
func (attr OrganizationProfileAttr) HasRepository(repo string) bool {
	if len(attr.Repositories) == 1 && attr.Repositories[0] == "*" {
		return true
	}

	return slices.Contains(attr.Repositories, repo)
}

// PipelineProfileAttr is a placeholder for future pipeline profile attributes.
// Any future slice fields should be treated as immutable after construction.
type PipelineProfileAttr struct {
	// TODO: Add pipeline-specific attributes when implementing pipeline profiles
}

// AuthorizedProfile encapsulates a matcher with typed profile attributes.
// The generic parameter T allows type-safe access to profile-specific attributes.
type AuthorizedProfile[T any] struct {
	matcher Matcher
	Attrs   T
}

// NewAuthorizedProfile creates a new AuthorizedProfile with the given matcher and attributes.
func NewAuthorizedProfile[T any](matcher Matcher, attrs T) AuthorizedProfile[T] {
	return AuthorizedProfile[T]{
		matcher: matcher,
		Attrs:   attrs,
	}
}

// Match evaluates the profile's match conditions against the provided claims.
// Returns a MatchResult containing:
// - Success: Matched=true, Matches populated
// - Pattern mismatch: Matched=false, Attempt populated
// - Validation error: Err populated
func (ap AuthorizedProfile[T]) Match(claims ClaimValueLookup) MatchResult {
	return ap.matcher(claims)
}
