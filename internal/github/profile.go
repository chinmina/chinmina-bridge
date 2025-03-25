package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"

	"slices"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

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
		return
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

// Update the currently stored organization profile
func (p *ProfileStore) Update(profile *ProfileConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config.Organization = profile.Organization
}

func FetchOrganizationProfile(ctx context.Context, profileURL url.URL, gh Client) (ProfileConfig, error) {
	profile, err := LoadProfile(ctx, gh, profileURL)
	if err != nil {
		return ProfileConfig{}, err
	}

	return profile, nil
}

// DecomposePath into the owner, repo, and path (no http prefix), assuming the
// path is in the format host/owner/repo/path_seg1/path_seg2/...
func DecomposePath(url url.URL) (string, string, string) {

	path := url.Path

	// Extract org_name & repo_name
	refined_path, _ := strings.CutPrefix(path, "/")

	// Eg: "/cultureamp/chinmina/docs/profile.yaml"
	remainingPath := strings.SplitN(refined_path, "/", 3)

	if len(remainingPath) != 3 {
		return "", "", ""
	}

	orgName, repoName, filePath := remainingPath[0], remainingPath[1], remainingPath[2]

	return orgName, repoName, filePath
}

func GetProfile(ctx context.Context, gh Client, orgProfileURI url.URL) (string, error) {
	// get the profile
	owner, repo, path := DecomposePath(orgProfileURI)
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

func LoadProfile(ctx context.Context, gh Client, orgProfileURL url.URL) (ProfileConfig, error) {
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

	log.Info().Str("url", orgProfileURL.String()).Msg("organization profile configuration loaded")

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

func (config *ProfileConfig) HasRepository(profileName string, repo string) bool {
	profile, ok := config.LookupProfile(profileName)
	if !ok {
		return false
	}

	return slices.Contains(profile.Repositories, repo)
}
