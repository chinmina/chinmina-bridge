package profile

import "slices"

// --- Attribute types (leaf types) ---

// OrganizationProfileAttr contains the attributes for an organization profile.
// Slice fields are expected to be treated as immutable after construction.
// Callers should not modify slice contents after passing to
// NewAuthorizedProfile or NewProfileStoreOf.
type OrganizationProfileAttr struct {
	Repositories []string
	Permissions  []string
}

// HasRepository checks if the given repository is included in the profile's
// repositories. Supports wildcard "*" to match any repository.
func (attr OrganizationProfileAttr) HasRepository(repo string) bool {
	return attr.allowAllRepositories() ||
		slices.Contains(attr.Repositories, repo)
}

// GetRepositories returns the list of repositories allowed by the profile.
// If the profile allows all repositories, it returns nil to signify this.
func (attr OrganizationProfileAttr) GetRepositories() []string {
	if attr.allowAllRepositories() {
		return nil // nil means all repositories
	}
	return attr.Repositories
}

// allowAllRepositories returns true if the profile allows access to all
// repositories accessible to the Chinmina installation. This is signified by
// the single "*" entry.
func (attr OrganizationProfileAttr) allowAllRepositories() bool {
	return len(attr.Repositories) == 1 && attr.Repositories[0] == "*"
}

// PipelineProfileAttr is a placeholder for future pipeline profile attributes.
// Any future slice fields should be treated as immutable after construction.
type PipelineProfileAttr struct {
	// TODO: Add pipeline-specific attributes when implementing pipeline profiles
}

// --- AuthorizedProfile (uses attribute types) ---

// AuthorizedProfile encapsulates a matcher with typed profile attributes.
// The generic parameter T allows type-safe access to profile-specific attributes.
type AuthorizedProfile[T any] struct {
	matcher Matcher
	Attrs   T
}

// Match evaluates the profile's match conditions against the provided claims.
// Returns a MatchResult containing:
// - Success: Matched=true, Matches populated
// - Pattern mismatch: Matched=false, Attempt populated
// - Validation error: Err populated
func (ap AuthorizedProfile[T]) Match(claims ClaimValueLookup) MatchResult {
	return ap.matcher(claims)
}

// --- ProfileStoreOf (stores AuthorizedProfiles) ---

// ProfileStoreOf provides immutable type-safe storage and retrieval of authorized profiles.
// The generic parameter T constrains the type of profile attributes stored.
// Once created, ProfileStoreOf cannot be modified.
type ProfileStoreOf[T any] struct {
	profiles        map[string]AuthorizedProfile[T]
	invalidProfiles map[string]error
}

// Get retrieves an authorized profile by name.
// Returns ProfileUnavailableError if the profile failed validation.
// Returns ProfileNotFoundError if the profile does not exist.
func (ps ProfileStoreOf[T]) Get(name string) (AuthorizedProfile[T], error) {
	if profile, found := ps.profiles[name]; found {
		return profile, nil
	}

	// in a stable configuration, valid profiles are the common case. Check for
	// invalidity second to avoid a mostly wasted map lookup.
	if err, found := ps.invalidProfiles[name]; found {
		return AuthorizedProfile[T]{}, ProfileUnavailableError{
			Name:  name,
			Cause: err,
		}
	}

	return AuthorizedProfile[T]{}, ProfileNotFoundError{Name: name}
}

// ProfileCount returns the number of valid profiles stored.
func (ps ProfileStoreOf[T]) ProfileCount() int {
	return len(ps.profiles)
}

// InvalidProfileCount returns the number of invalid profiles stored.
func (ps ProfileStoreOf[T]) InvalidProfileCount() int {
	return len(ps.invalidProfiles)
}

// --- Profiles (aggregates ProfileStoreOf) ---

// Profiles holds compiled runtime profiles for organization-level configuration.
// It combines organization profiles with pipeline defaults and a content digest.
// Once created, Profiles is immutable.
type Profiles struct {
	orgProfiles      ProfileStoreOf[OrganizationProfileAttr]
	pipelineDefaults []string
	digest           string
	location         string
}

// GetOrgProfile retrieves an organization profile by name.
// Returns ProfileStoreNotLoadedError if profiles have not been loaded.
func (p Profiles) GetOrgProfile(name string) (AuthorizedProfile[OrganizationProfileAttr], error) {
	if !p.IsLoaded() {
		// Organization profiles can only be defined in configuration. If a profile is requested
		// before loading, it indicates that the service has not been able to load profiles.
		return AuthorizedProfile[OrganizationProfileAttr]{}, ProfileStoreNotLoadedError{}
	}
	return p.orgProfiles.Get(name)
}

// GetPipelineDefaults returns the default permissions for pipelines. Falls back
// to ["contents:read"] if not configured. Guaranteed to return a result: either
// the default or the configuration.
func (p Profiles) GetPipelineDefaults() []string {
	if len(p.pipelineDefaults) == 0 {
		return []string{"contents:read"}
	}

	// Return a copy to preserve immutability
	return slices.Clone(p.pipelineDefaults)
}

// Digest returns the content digest of the profile configuration.
func (p Profiles) Digest() string {
	return p.digest
}

// IsLoaded returns true if profiles have been successfully loaded.
func (p Profiles) IsLoaded() bool {
	return len(p.digest) > 0
}

// Stats returns statistics about the loaded profiles including valid/invalid
// counts.
func (p Profiles) Stats() ProfilesStats {
	return ProfilesStats{
		OrganizationProfileCount:        p.orgProfiles.ProfileCount(),
		OrganizationInvalidProfileCount: p.orgProfiles.InvalidProfileCount(),
		Digest:                          p.digest,
		Location:                        p.location,
	}
}

// ProfilesStats provides statistics about loaded profiles.
type ProfilesStats struct {
	OrganizationProfileCount        int
	OrganizationInvalidProfileCount int
	Digest                          string
	Location                        string
}

// NewAuthorizedProfile creates a new AuthorizedProfile with the given matcher and attributes.
func NewAuthorizedProfile[T any](matcher Matcher, attrs T) AuthorizedProfile[T] {
	return AuthorizedProfile[T]{
		matcher: matcher,
		Attrs:   attrs,
	}
}

// NewProfileStoreOf creates a new immutable ProfileStoreOf instance with the given profiles.
// Invalid profiles are tracked separately and returned as ProfileUnavailableError on Get().
// The maps are copied to ensure immutability.
// Note: Profile attributes of type T are shallow copied. Callers should treat attribute
// contents (e.g., slices) as immutable after passing them to this function.
func NewProfileStoreOf[T any](profiles map[string]AuthorizedProfile[T], invalidProfiles map[string]error) ProfileStoreOf[T] {
	// Copy the profiles map to ensure immutability
	profilesCopy := make(map[string]AuthorizedProfile[T], len(profiles))
	for k, v := range profiles {
		profilesCopy[k] = v
	}

	// Copy the invalidProfiles map to ensure immutability
	invalidProfilesCopy := make(map[string]error, len(invalidProfiles))
	for k, v := range invalidProfiles {
		invalidProfilesCopy[k] = v
	}

	return ProfileStoreOf[T]{
		profiles:        profilesCopy,
		invalidProfiles: invalidProfilesCopy,
	}
}

// NewProfiles creates a new Profiles instance.
// The pipelineDefaults slice is copied to ensure immutability.
func NewProfiles(
	orgProfiles ProfileStoreOf[OrganizationProfileAttr],
	pipelineDefaults []string,
	digest string,
	location string,
) Profiles {
	// Copy pipelineDefaults to ensure immutability
	defaultsCopy := make([]string, len(pipelineDefaults))
	copy(defaultsCopy, pipelineDefaults)

	return Profiles{
		orgProfiles:      orgProfiles,
		pipelineDefaults: defaultsCopy,
		digest:           digest,
		location:         location,
	}
}
