package github

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

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

func (p ProfileConfig) MarshalZerologObject(e *zerolog.Event) {
	result, err := json.Marshal(p)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal ProfileConfig")
	}
	e.Str("profileConfig", string(result))
}

func (c *Client) OrganizationProfile(ctx context.Context, profileChan chan (*ProfileConfig)) (*ProfileConfig, error) {
	// If there are profiles in the channel, return the first one.
	// Otherwise we will return the existing org profile.
	emptyProfile := ProfileConfig{}
	for {
		select {
		case profile := <-profileChan:
			// Check whether the received profile differs
			if !c.organizationProfile.CompareAndSwap(profile, profile) {
				c.organizationProfile.Store(profile)
				log.Info().EmbedObject(c.organizationProfile.Load()).Msg("organization profile configuration loaded")
			} 
		default:
			// This comparison needs to be atomic, because this comparison could be made across threads.
			// Handle the initial case where the profile is not loaded
			if c.organizationProfile.CompareAndSwap(nil, &emptyProfile) {
				return c.organizationProfile.Load(), errors.New("organization profile not loaded")
			}
		}
		return c.organizationProfile.Load(), nil
	}
}

func (c *Client) FetchOrganizationProfile(profileURL string, profileChan chan (*ProfileConfig)) error {
	profile, err := LoadProfile(context.Background(), *c, profileURL)
	if err != nil {
		return err
	}
	profileChan <- &profile
	return nil
}

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
		log.Info().Err(err).Msg("organization profile load failed, continuing")
		return "", err
	}
	return profile.GetContent()
}

func ValidateProfile(ctx context.Context, profile string) (ProfileConfig, error) {
	profileConfig := ProfileConfig{}
	err := yaml.UnmarshalStrict([]byte(profile), &profileConfig)
	if err != nil {
		log.Info().Err(err).Msg("organization profile invalid")
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
