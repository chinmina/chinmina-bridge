package githubtest

import (
	"github.com/chinmina/chinmina-bridge/internal/github"
)

func createTestProfile() github.ProfileConfig {
	// Create profiles with compiled matchers (empty match rules)
	return github.NewTestProfileConfig(
		github.NewTestProfile("simple-profile", []string{"repo-1", "repo-2"}, []string{"read", "write"}),
		github.NewTestProfile("non-default-profile", []string{"secret-repo", "another-secret-repo"}, []string{"contents:read", "packages:read"}),
	)
}

// CreateTestProfileStore creates a ProfileStore for testing with sample profiles.
// All profiles have empty match rules and compiled matchers.
func CreateTestProfileStore() *github.ProfileStore {
	testProfile := createTestProfile()
	store := github.NewProfileStore()
	store.Update(&testProfile)

	return store
}
