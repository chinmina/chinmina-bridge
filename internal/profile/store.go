package profile

import (
	"errors"
	"sync"

	"github.com/rs/zerolog/log"
)

type ProfileStore struct {
	mu     sync.RWMutex
	config ProfileConfig
}

func NewProfileStore() *ProfileStore {
	return &ProfileStore{}
}

func (p *ProfileStore) GetProfileFromStore(name string) (Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.config.LookupProfile(name)
}

// GetOrganizationProfile retrieves an organization profile and converts it to
// the runtime AuthorizedProfile format.
// This is a bridge method to support gradual migration to the new profile API.
func (p *ProfileStore) GetOrganizationProfile(name string) (AuthorizedProfile[OrganizationProfileAttr], error) {
	profile, err := p.GetProfileFromStore(name)
	if err != nil {
		return AuthorizedProfile[OrganizationProfileAttr]{}, err
	}

	// Convert serialization format (Profile) to runtime format (AuthorizedProfile)
	attrs := OrganizationProfileAttr{
		Repositories: profile.Repositories,
		Permissions:  profile.Permissions,
	}

	// Extract the compiled matcher from the profile
	// Note: Matches() returns a MatchResult, but we need the underlying Matcher
	// We access this through a type assertion on the profile's matcher field
	matcher := func(claims ClaimValueLookup) MatchResult {
		return profile.Matches(claims)
	}

	return NewAuthorizedProfile(matcher, attrs), nil
}

func (p *ProfileStore) GetOrganization() (ProfileConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.config.Organization.Profiles) == 0 &&
		len(p.config.Organization.InvalidProfiles) == 0 {
		return p.config, errors.New("organization profile not loaded")
	}

	return p.config, nil
}

// Update the currently stored organization profile. Logs at info level if the
// profile content changed (based on digest), or at debug level if unchanged.
func (p *ProfileStore) Update(profile ProfileConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldDigest := p.config.Digest()
	newDigest := profile.Digest()

	// by default, only log when the source has actually changed content
	if oldDigest != newDigest {
		log.Info().Msg("organization profiles: updated")
	} else {
		log.Debug().Msg("organization profiles: no changes detected")
	}

	p.config = profile
}
