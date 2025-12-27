package profile

// OrganizationProfileAttr contains the attributes for an organization profile.
type OrganizationProfileAttr struct {
	Repositories []string
	Permissions  []string
}

// PipelineProfileAttr is a placeholder for future pipeline profile attributes.
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
