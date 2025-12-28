package profile

import (
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

// GetPipelineDefaults returns the default permissions for pipelines.
// Falls back to ["contents:read"] if not configured.
func (p *ProfileStore) GetPipelineDefaults() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.profiles.GetPipelineDefaults()
}

// Update the currently stored organization profile. Logs at info level if the
// profile content changed (based on digest), or at debug level if unchanged.
func (p *ProfileStore) Update(profiles Profiles) {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldDigest := p.profiles.Digest()
	newDigest := profiles.Digest()

	// by default, only log when the source has actually changed content
	if oldDigest != newDigest {
		log.Info().Msg("organization profiles: updated")
	} else {
		log.Debug().Msg("organization profiles: no changes detected")
	}

	p.profiles = profiles
}
