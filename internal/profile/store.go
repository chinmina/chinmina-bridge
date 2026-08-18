package profile

import (
	"context"
	"sync"

	"log/slog"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type ProfileStore struct {
	mu       sync.RWMutex
	profiles Profiles
}

func NewProfileStore() *ProfileStore {
	return &ProfileStore{}
}

// NewDefaultProfiles creates a minimal default Profiles with only the "default"
// pipeline profile using hard-coded default permissions ["contents:read", "metadata:read"].
// This provides a baseline profile set so the ProfileStore is never unloaded.
func NewDefaultProfiles() Profiles {
	// Create universal matcher (empty match rules always match)
	defaultMatcher := CompositeMatcher()

	// Create pipeline profiles map with only "default", which always mints
	// through the default app: this generation exists precisely because no
	// configuration has been loaded, so no other app can have been named.
	pipelineProfiles := map[string]AuthorizedProfile[PipelineProfileAttr]{
		"default": NewAuthorizedProfile(defaultMatcher, PipelineProfileAttr{
			Permissions: []string{"contents:read", "metadata:read"},
			App:         github.DefaultAppName,
		}),
	}

	// Create empty organization profiles
	orgProfiles := NewProfileStoreOf(
		map[string]AuthorizedProfile[OrganizationProfileAttr]{},
		map[string]error{},
	)

	// Create pipeline profile store
	pipelineProfileStore := NewProfileStoreOf(pipelineProfiles, map[string]error{})

	// Synthetic digest to distinguish from loaded profiles
	digest := "default-profile:v1"

	return NewProfiles(orgProfiles, pipelineProfileStore, digest, "")
}

// GetOrganizationProfile retrieves an organization profile in runtime format,
// together with the digest of the configuration generation it came from. Both
// values are read under a single lock so a caller cannot combine a profile
// from one generation with the digest of another.
func (p *ProfileStore) GetOrganizationProfile(name string) (AuthorizedProfile[OrganizationProfileAttr], string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	authProfile, err := p.profiles.GetOrgProfile(name)
	return authProfile, p.profiles.Digest(), err
}

// GetPipelineProfile retrieves a pipeline profile in runtime format, together
// with the digest of the configuration generation it came from. See
// GetOrganizationProfile for why the digest is returned alongside.
func (p *ProfileStore) GetPipelineProfile(name string) (AuthorizedProfile[PipelineProfileAttr], string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	authProfile, err := p.profiles.GetPipelineProfile(name)
	return authProfile, p.profiles.Digest(), err
}

// Digest returns the content digest of the currently loaded profiles, for
// callers reporting on configuration state. Request handling must NOT use it:
// the digest a request is keyed on has to be the one returned alongside the
// profile by GetOrganizationProfile or GetPipelineProfile, under the same
// lock, or a refresh landing in between would key a token on a generation
// other than the one that authorized it.
func (p *ProfileStore) Digest() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.profiles.Digest()
}

// Update the currently stored profiles. Logs at info level if the
// profile content changed (based on digest), or at debug level if unchanged.
func (p *ProfileStore) Update(ctx context.Context, profiles Profiles) {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldDigest := p.profiles.Digest()
	newDigest := profiles.Digest()

	stats := profiles.Stats()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("profile.digest_current", oldDigest),
		attribute.String("profile.digest_updated", newDigest),
		attribute.Bool("profile.digest_changed", oldDigest != newDigest),
		attribute.Int("profile.organization.valid_count", stats.OrganizationProfileCount),
		attribute.Int("profile.organization.invalid_count", stats.OrganizationInvalidProfileCount),
		attribute.Int("profile.pipeline.valid_count", stats.PipelineProfileCount),
		attribute.Int("profile.pipeline.invalid_count", stats.PipelineInvalidProfileCount),
	)

	// by default, only log when the source has actually changed content
	if oldDigest != newDigest {
		slog.Info("profiles: updated",
			"stats", stats,
			"previousStats", p.profiles.Stats())
	} else {
		slog.Debug("profiles: no changes detected",
			"stats", stats)
	}

	p.profiles = profiles
}

// FetchOrganizationProfile loads organization profile configuration from GitHub.
// This is the main entry point for production code.
//
// usableApp travels with the fetch rather than being captured once at startup
// so that the background refresh path validates against the same registry the
// synchronous path does. A profile's validity depends on both the YAML and the
// registry, and only one of those is reflected in the digest.
func FetchOrganizationProfile(ctx context.Context, orgProfileLocation string, gh GitHubClient, usableApp AppLookup) (Profiles, error) {
	return load(ctx, gh, orgProfileLocation, usableApp)
}

// load retrieves, parses, and compiles profile configuration from GitHub.
func load(ctx context.Context, gh GitHubClient, orgProfileLocation string, usableApp AppLookup) (Profiles, error) {
	yamlContent, err := retrieve(ctx, gh, orgProfileLocation)
	if err != nil {
		return Profiles{}, err
	}

	config, digest, err := parse(yamlContent)
	if err != nil {
		return Profiles{}, err
	}

	profiles, err := compile(config, digest, orgProfileLocation, usableApp)
	if err != nil {
		return Profiles{}, err
	}

	return profiles, nil
}
