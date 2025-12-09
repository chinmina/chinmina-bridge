package testhelpers

import "github.com/chinmina/chinmina-bridge/internal/github"

var testProfile = github.ProfileConfig{
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
		Profiles: []github.Profile{
			{
				Name:         "simple-profile",
				Repositories: []string{"repo-1", "repo-2"},
				Permissions:  []string{"read", "write"},
			},
			{
				Name:         "non-default-profile",
				Repositories: []string{"secret-repo", "another-secret-repo"},
				Permissions:  []string{"contents:read", "packages:read"},
			},
		},
	},
}

func CreateTestProfileStore() *github.ProfileStore {
	store := github.NewProfileStore()
	store.Update(&testProfile)

	return store
}
