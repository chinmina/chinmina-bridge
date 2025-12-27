package profile

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
