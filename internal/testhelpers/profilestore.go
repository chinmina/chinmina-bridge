package testhelpers

import "github.com/chinmina/chinmina-bridge/internal/github"

var testProfile = github.ProfileConfig{
	Organization: struct {
		Profiles []github.Profile `yaml:"profiles"`
	}{
		Profiles: []github.Profile{
			{
				Name:         "simple-profile",
				Repositories: []string{"repo-1", "repo-2"},
				Permissions:  []string{"read", "write"},
			},
		},
	},
}

func CreateTestProfileStore() *github.ProfileStore {
	store := github.NewProfileStore()
	store.Update(&testProfile)

	return store
}
