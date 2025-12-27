package profiletest

import (
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

func createTestProfiles() profile.Profiles {
	// Create profile configuration with compiled matchers (empty match rules)
	profileConfig := profile.NewTestProfileConfig(
		profile.NewTestProfile("simple-profile", []string{"repo-1", "repo-2"}, []string{"read", "write"}),
		profile.NewTestProfile("non-default-profile", []string{"secret-repo", "another-secret-repo"}, []string{"contents:read", "packages:read"}),
	)

	// Compile to runtime format
	return profile.CompileProfiles(profileConfig)
}

// CreateTestProfileStore creates a ProfileStore for testing with sample profiles.
// All profiles have empty match rules and compiled matchers.
func CreateTestProfileStore() *profile.ProfileStore {
	testProfiles := createTestProfiles()
	store := profile.NewProfileStore()
	store.Update(testProfiles)

	return store
}
