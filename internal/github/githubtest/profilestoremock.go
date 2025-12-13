package githubtest

import (
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

func createTestProfile() profile.ProfileConfig {
	// Create profiles with compiled matchers (empty match rules)
	return profile.NewTestProfileConfig(
		profile.NewTestProfile("simple-profile", []string{"repo-1", "repo-2"}, []string{"read", "write"}),
		profile.NewTestProfile("non-default-profile", []string{"secret-repo", "another-secret-repo"}, []string{"contents:read", "packages:read"}),
	)
}

// CreateTestProfileStore creates a ProfileStore for testing with sample profiles.
// All profiles have empty match rules and compiled matchers.
func CreateTestProfileStore() *profile.ProfileStore {
	testProfile := createTestProfile()
	store := profile.NewProfileStore()
	store.Update(&testProfile)

	return store
}
