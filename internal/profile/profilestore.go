package profile

import "sync"

// ProfileStoreOf provides type-safe storage and retrieval of authorized profiles.
// The generic parameter T constrains the type of profile attributes stored.
type ProfileStoreOf[T any] struct {
	mu       sync.RWMutex
	profiles map[string]AuthorizedProfile[T]
}

// NewProfileStoreOf creates a new ProfileStoreOf instance.
func NewProfileStoreOf[T any]() *ProfileStoreOf[T] {
	return &ProfileStoreOf[T]{
		profiles: make(map[string]AuthorizedProfile[T]),
	}
}

// Get retrieves an authorized profile by name.
// Returns ProfileNotFoundError if the profile does not exist.
func (ps *ProfileStoreOf[T]) Get(name string) (AuthorizedProfile[T], error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	profile, found := ps.profiles[name]
	if !found {
		return AuthorizedProfile[T]{}, ProfileNotFoundError{Name: name}
	}

	return profile, nil
}

// Update stores or updates an authorized profile.
func (ps *ProfileStoreOf[T]) Update(name string, profile AuthorizedProfile[T]) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.profiles[name] = profile
}
