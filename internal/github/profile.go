package github

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"slices"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type ProfileStore struct {
	mu     sync.Mutex
	config ProfileConfig
}

type ProfileConfig struct {
	Organization struct {
		Defaults struct {
			Permissions []string `yaml:"permissions"`
		} `yaml:"defaults"`
		Profiles []Profile `yaml:"profiles"`
	} `yaml:"organization"`
}

type MatchRule struct {
	Claim        string `yaml:"claim"`
	Value        string `yaml:"value"`
	ValuePattern string `yaml:"valuePattern"`
}

type Profile struct {
	Name         string      `yaml:"name"`
	Match        []MatchRule `yaml:"match"`
	Repositories []string    `yaml:"repositories"`
	Permissions  []string    `yaml:"permissions"`
}

func (p ProfileConfig) MarshalZerologObject(e *zerolog.Event) {
	result, err := json.Marshal(p)
	if err != nil {
		e.Err(err).Msg("failed to marshal ProfileConfig")
		return
	}

	e.Str("profileConfig", string(result))
}

func NewProfileStore() *ProfileStore {
	return &ProfileStore{}
}

func (p *ProfileStore) GetProfileFromStore(name string) (Profile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	profile, ok := p.config.LookupProfile(name)
	if !ok {
		return Profile{}, errors.New("profile not found")
	}

	return profile, nil
}

func (p *ProfileStore) GetOrganization() (ProfileConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.config.Organization.Profiles) == 0 {
		return p.config, errors.New("organization profile not loaded")
	}

	return p.config, nil
}

// Update the currently stored organization profile
func (p *ProfileStore) Update(profile *ProfileConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config.Organization = profile.Organization
}

func FetchOrganizationProfile(ctx context.Context, orgProfileLocation string, gh Client) (ProfileConfig, error) {
	profile, err := LoadProfile(ctx, gh, orgProfileLocation)
	if err != nil {
		return ProfileConfig{}, err
	}

	return profile, nil
}

// DecomposePath into the owner, repo, and path (no http prefix), assuming the
// path is in the format host/owner/repo/path_seg1/path_seg2/...
func DecomposePath(profileLocation string) (string, string, string) {

	// Eg: "/cultureamp/chinmina/docs/profile.yaml"
	location := strings.SplitN(profileLocation, ":", 3)

	if len(location) != 3 {
		return "", "", ""
	}

	orgName, repoName, filePath := location[0], location[1], location[2]

	return orgName, repoName, filePath
}

func GetProfile(ctx context.Context, gh Client, orgProfileLocation string) (string, error) {
	// get the profile
	owner, repo, path := DecomposePath(orgProfileLocation)
	profile, _, _, err := gh.client.Repositories.GetContents(ctx, owner, repo, path, nil)
	if err != nil {
		log.Info().Err(err).Str("repo", repo).Str("owner", owner).Str("path", path).Msg("organization profile load failed, continuing")
		return "", err
	}

	return profile.GetContent()
}

func ValidateProfile(ctx context.Context, profile string) (ProfileConfig, error) {
	profileConfig := ProfileConfig{}

	dec := yaml.NewDecoder(strings.NewReader(profile))

	// Loading the profiles MUST fail in the presence of unknown fields otherwise
	// a misconfiguration (like a typo) could lead to unauthorized access through
	// privilege escalation.
	dec.KnownFields(true)

	err := dec.Decode(&profileConfig)
	if err != nil {
		log.Info().Err(err).Msg("organization profile invalid")
		return ProfileConfig{}, err
	}

	return profileConfig, nil
}

func LoadProfile(ctx context.Context, gh Client, orgProfileLocation string) (ProfileConfig, error) {
	// get the profile
	profile, err := GetProfile(ctx, gh, orgProfileLocation)
	if err != nil {
		return ProfileConfig{}, err
	}

	// validate the profile
	profileConfig, err := ValidateProfile(ctx, profile)
	if err != nil {
		return ProfileConfig{}, err
	}

	log.Info().Str("url", orgProfileLocation).Msg("organization profile configuration loaded")

	return profileConfig, nil
}

func (config *ProfileConfig) LookupProfile(name string) (Profile, bool) {
	for _, profile := range config.Organization.Profiles {
		if profile.Name == name {
			return profile, true
		}
	}

	return Profile{}, false
}

// GetDefaultPermissions returns the configured default permissions for repo:default.
// Falls back to ["contents:read"] if not configured.
func (config *ProfileConfig) GetDefaultPermissions() []string {
	if len(config.Organization.Defaults.Permissions) == 0 {
		return []string{"contents:read"}
	}
	return config.Organization.Defaults.Permissions
}

func (config Profile) HasRepository(repo string) bool {
	return slices.Contains(config.Repositories, repo)
}
