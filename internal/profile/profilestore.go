package profile

import "slices"

// ProfileStoreOf provides immutable type-safe storage and retrieval of authorized profiles.
// The generic parameter T constrains the type of profile attributes stored.
// Once created, ProfileStoreOf cannot be modified.
type ProfileStoreOf[T any] struct {
	profiles        map[string]AuthorizedProfile[T]
	invalidProfiles map[string]error
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

// Get retrieves an authorized profile by name.
// Returns ProfileUnavailableError if the profile failed validation.
// Returns ProfileNotFoundError if the profile does not exist.
func (ps ProfileStoreOf[T]) Get(name string) (AuthorizedProfile[T], error) {
	// Check invalid profiles first
	if err, found := ps.invalidProfiles[name]; found {
		return AuthorizedProfile[T]{}, ProfileUnavailableError{
			Name:  name,
			Cause: err,
		}
	}

	profile, found := ps.profiles[name]
	if !found {
		return AuthorizedProfile[T]{}, ProfileNotFoundError{Name: name}
	}

	return profile, nil
}

// Profiles holds compiled runtime profiles for organization-level configuration.
// It combines organization profiles with pipeline defaults and a content digest.
// Once created, Profiles is immutable.
type Profiles struct {
	orgProfiles      ProfileStoreOf[OrganizationProfileAttr]
	pipelineDefaults []string
	digest           string
}

// NewProfiles creates a new Profiles instance.
// The pipelineDefaults slice is copied to ensure immutability.
func NewProfiles(
	orgProfiles ProfileStoreOf[OrganizationProfileAttr],
	pipelineDefaults []string,
	digest string,
) Profiles {
	// Copy pipelineDefaults to ensure immutability
	defaultsCopy := make([]string, len(pipelineDefaults))
	copy(defaultsCopy, pipelineDefaults)

	return Profiles{
		orgProfiles:      orgProfiles,
		pipelineDefaults: defaultsCopy,
		digest:           digest,
	}
}

// GetOrgProfile retrieves an organization profile by name.
// Returns ProfileStoreNotLoadedError if profiles have not been loaded.
func (p Profiles) GetOrgProfile(name string) (AuthorizedProfile[OrganizationProfileAttr], error) {
	if !p.IsLoaded() {
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
