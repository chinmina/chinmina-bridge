package profile

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"
)

type ProfileStore struct {
	mu       sync.RWMutex
	profiles Profiles
}

func NewProfileStore() *ProfileStore {
	return &ProfileStore{}
}

// GetOrganizationProfile retrieves an organization profile in runtime format.
func (p *ProfileStore) GetOrganizationProfile(name string) (AuthorizedProfile[OrganizationProfileAttr], error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.profiles.GetOrgProfile(name)
}

// GetPipelineProfile retrieves a pipeline profile in runtime format.
func (p *ProfileStore) GetPipelineProfile(name string) (AuthorizedProfile[PipelineProfileAttr], error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.profiles.GetPipelineProfile(name)
}

// Update the currently stored profiles. Logs at info level if the
// profile content changed (based on digest), or at debug level if unchanged.
func (p *ProfileStore) Update(profiles Profiles) {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldDigest := p.profiles.Digest()
	newDigest := profiles.Digest()

	// by default, only log when the source has actually changed content
	if oldDigest != newDigest {
		log.Info().
			Interface("stats", profiles.Stats()).
			Interface("previousStats", p.profiles.Stats()).
			Msg("profiles: updated")
	} else {
		log.Debug().
			Interface("stats", profiles.Stats()).
			Msg("profiles: no changes detected")
	}

	p.profiles = profiles
}

// FetchOrganizationProfile loads organization profile configuration from GitHub.
// This is the main entry point for production code.
func FetchOrganizationProfile(ctx context.Context, orgProfileLocation string, gh GitHubClient) (Profiles, error) {
	return load(ctx, gh, orgProfileLocation)
}

// load retrieves, parses, and compiles profile configuration from GitHub.
func load(ctx context.Context, gh GitHubClient, orgProfileLocation string) (Profiles, error) {
	yamlContent, err := retrieve(ctx, gh, orgProfileLocation)
	if err != nil {
		return Profiles{}, err
	}

	config, digest, err := parse(yamlContent)
	if err != nil {
		return Profiles{}, err
	}

	profiles := compile(config, digest, orgProfileLocation)

	return profiles, nil
}
