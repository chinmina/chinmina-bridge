package githubtest

import (
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

func createTestProfile() github.ProfileConfig {
	// Create profiles with compiled matchers (empty match rules)
	profiles := []github.Profile{
		{
			Name:            "simple-profile",
			Repositories:    []string{"repo-1", "repo-2"},
			Permissions:     []string{"read", "write"},
			Match:           []github.MatchRule{},
			CompiledMatcher: profile.CompositeMatcher(), // Empty matcher for no match rules
		},
		{
			Name:            "non-default-profile",
			Repositories:    []string{"secret-repo", "another-secret-repo"},
			Permissions:     []string{"contents:read", "packages:read"},
			Match:           []github.MatchRule{},
			CompiledMatcher: profile.CompositeMatcher(), // Empty matcher for no match rules
		},
	}

	return github.ProfileConfig{
		Organization: struct {
			Defaults struct {
				Permissions []string `yaml:"permissions"`
			} `yaml:"defaults"`
			Profiles []github.Profile `yaml:"profiles"`
		}{
			Defaults: struct {
				Permissions []string `yaml:"permissions"`
			}{
				Permissions: []string{"contents:read"},
			},
			Profiles: profiles,
		},
	}
}

// CreateTestProfileStore creates a ProfileStore for testing with sample profiles.
// All profiles have empty match rules and compiled matchers.
func CreateTestProfileStore() *github.ProfileStore {
	testProfile := createTestProfile()
	store := github.NewProfileStore()
	store.Update(&testProfile, nil)

	return store
}
