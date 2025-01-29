package github

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/chinmina/chinmina-bridge/internal/audit"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

// Decomposes the path into the owner, repo, and path (no http prefix)
func DecomposePath(path string) (string, string, string) {
	parts := strings.SplitN(path, "/", 4)
	if len(parts) < 4 {
		return "", "", ""
	}
	return parts[1], parts[2], parts[3]
}

func GetProfile(ctx context.Context, gh Client, orgProfileURI string) (string, error) {

	// get the profile
	owner, repo, path := DecomposePath(orgProfileURI)
	profile, _, _, err := gh.client.Repositories.GetContents(ctx, owner, repo, path, nil)
	if err != nil {
		entry := audit.Log(ctx)
		entry.Error = fmt.Sprintf("Unable to load organization profile %s", err.Error())
		return "", err
	}
	return profile.GetContent()
}

type ProfileConfig struct {
	Organization struct {
		Profiles []Profile `yaml:"profiles"`
	} `yaml:"organization"`
}

type Profile struct {
	Name         string   `yaml:"name"`
	Repositories []string `yaml:"repositories"`
	Permissions  []string `yaml:"permissions"`
}

func ValidateProfile(ctx context.Context, profile string) (ProfileConfig, error) {
	profileConfig := ProfileConfig{}
	err := yaml.UnmarshalStrict([]byte(profile), &profileConfig)
	if err != nil {
		entry := audit.Log(ctx)
		entry.Error = fmt.Sprintf("Organization profile invalid %s", err.Error())
		return ProfileConfig{}, err
	}
	return profileConfig, nil
}

func LoadProfile(ctx context.Context, gh Client, orgProfileURL string) (ProfileConfig, error) {
	// get the profile
	profile, err := GetProfile(ctx, gh, orgProfileURL)
	if err != nil {
		return ProfileConfig{}, err
	}

	// validate the profile
	profileConfig, err := ValidateProfile(ctx, profile)
	if err != nil {
		return ProfileConfig{}, err
	}
	//Store it in the shared GitHub context so it can be referenced in the Vendor functionality
	log.Info().Str("url", orgProfileURL).Msg("organization profile configuration loaded")

	return profileConfig, nil
}

func (config *ProfileConfig) HasProfile(name string) (Profile, bool) {
	for _, profile := range config.Organization.Profiles {
		if profile.Name == name {
			return profile, true
		}
	}
	return Profile{}, false
}

func (config *ProfileConfig) HasRepository(profileName string, repo string) bool {
	profile, ok := config.HasProfile(profileName)
	if !ok {
		return false
	}
	for _, repository := range profile.Repositories {
		if repository == repo {
			return true
		}
	}
	return false
}

func (c Client) OrganizationProfile(ctx context.Context) (ProfileConfig, error) {
	if reflect.DeepEqual(c.organizationProfile, ProfileConfig{}) {
		return c.organizationProfile, errors.New("organization profile not loaded")
	}
	return c.organizationProfile, nil
}

func (c *Client) FetchOrganizationProfile(profileURL string) error {
	profile, err := LoadProfile(context.Background(), *c, profileURL)
	if err != nil {
		return err
	}
	c.organizationProfile = profile
	return nil
}
