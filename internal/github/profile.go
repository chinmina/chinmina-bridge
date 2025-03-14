package github

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

// type ProfileStore struct {
// 	ProfileConfig *ProfileConfig
// }

type ProfileStore struct {
	mu     sync.Mutex
	config ProfileConfig
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

func (p ProfileConfig) MarshalZerologObject(e *zerolog.Event) {
	result, err := json.Marshal(p)
	if err != nil {
		e.Err(err).Msg("failed to marshal ProfileConfig")
	}
	e.Str("profileConfig", string(result))
}

func NewProfileStore() *ProfileStore {
	return &ProfileStore{}
}

func (p *ProfileStore) GetOrganization() (ProfileConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.config.Organization.Profiles) == 0 {
		return p.config, errors.New("organization profile not loaded")
	}
	return p.config, nil
}

// Not sure how we can possibly pass back an error here so we won't return one
func (p *ProfileStore) Update(profile *ProfileConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config.Organization = profile.Organization
	return
}

func FetchOrganizationProfile(profileURL string, gh Client) (ProfileConfig, error) {
	profile, err := LoadProfile(context.Background(), gh, profileURL)
	if err != nil {
		return ProfileConfig{}, err
	}

	return profile, nil
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
	client, err := gh.NewWithTokenAuth(ctx, owner, repo)
	if err != nil {
		return "", err
	}
	client.BaseURL = gh.client.BaseURL
	gh.client = client
	profile, _, _, err := gh.client.Repositories.GetContents(ctx, owner, repo, path, nil)
	if err != nil {
		log.Info().Err(err).Str("repo", repo).Str("owner", owner).Str("path", path).Msg("organization profile load failed, continuing")
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
