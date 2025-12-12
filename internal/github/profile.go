package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"slices"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type ProfileStore struct {
	mu             sync.Mutex
	config         ProfileConfig
	failedProfiles map[string]error // Tracks profiles that failed validation
}

func NewProfileStore() *ProfileStore {
	return &ProfileStore{}
}

func (p *ProfileStore) GetProfileFromStore(name string) (Profile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	profile, ok := p.config.LookupProfile(name)
	if ok {
		return profile, nil
	}

	// not found, check if it failed validation
	if err, failed := p.failedProfiles[name]; failed {
		return Profile{}, &ProfileUnavailableError{
			Name:  name,
			Cause: err,
		}
	}

	return Profile{}, errors.New("profile not found")
}

func (p *ProfileStore) GetOrganization() (ProfileConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.config.Organization.Profiles) == 0 {
		return p.config, errors.New("organization profile not loaded")
	}

	return p.config, nil
}

// Update the currently stored organization profile with failed profiles tracking
func (p *ProfileStore) Update(profile *ProfileConfig, failedProfiles map[string]error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config.Organization = profile.Organization
	p.failedProfiles = failedProfiles
}

type ProfileConfig struct {
	Organization struct {
		Defaults struct {
			Permissions []string `yaml:"permissions"`
		} `yaml:"defaults"`
		Profiles []Profile `yaml:"profiles"`
	} `yaml:"organization"`
}

func (p ProfileConfig) MarshalZerologObject(e *zerolog.Event) {
	result, err := json.Marshal(p)
	if err != nil {
		e.Err(err).Msg("failed to marshal ProfileConfig")
		return
	}

	e.Str("profileConfig", string(result))
}

// GetDefaultPermissions returns the configured default permissions for repo:default.
// Falls back to ["contents:read"] if not configured.
func (config *ProfileConfig) GetDefaultPermissions() []string {
	if len(config.Organization.Defaults.Permissions) == 0 {
		return []string{"contents:read"}
	}
	return config.Organization.Defaults.Permissions
}

func (config *ProfileConfig) LookupProfile(name string) (Profile, bool) {
	for _, profile := range config.Organization.Profiles {
		if profile.Name == name {
			return profile, true
		}
	}

	return Profile{}, false
}

type Profile struct {
	Name         string      `yaml:"name"`
	Match        []MatchRule `yaml:"match"`
	Repositories []string    `yaml:"repositories"`
	Permissions  []string    `yaml:"permissions"`

	// CompiledMatcher is the compiled matcher from Match rules.
	// Populated during profile loading, not from YAML.
	CompiledMatcher profile.Matcher `yaml:"-"`
}

func (config Profile) HasRepository(repo string) bool {
	return slices.Contains(config.Repositories, repo)
}

// Matches evaluates the profile's match conditions against the provided claims.
// Returns the matched claims for audit logging and a boolean indicating success.
// Panics if CompiledMatcher is nil (indicates profile wasn't properly loaded).
func (p Profile) Matches(claims profile.ClaimValueLookup) (matches []profile.ClaimMatch, ok bool) {
	if p.CompiledMatcher == nil {
		panic("profile matcher not compiled - profile must be loaded via LoadProfile")
	}
	return p.CompiledMatcher(claims)
}

type MatchRule struct {
	Claim        string `yaml:"claim"`
	Value        string `yaml:"value"`
	ValuePattern string `yaml:"valuePattern"`
}

// ProfileUnavailableError indicates a profile failed validation
type ProfileUnavailableError struct {
	Name  string
	Cause error
}

func (e *ProfileUnavailableError) Error() string {
	return fmt.Sprintf("profile %q unavailable: validation failed", e.Name)
}

func (e *ProfileUnavailableError) Unwrap() error {
	return e.Cause
}

// ValidateMatchRule validates that a match rule is well-formed:
// - Exactly one of value or valuePattern must be specified
// - The claim must be in the allowed list
func ValidateMatchRule(rule MatchRule) error {
	// Exactly one of value or valuePattern
	if rule.Value != "" && rule.ValuePattern != "" {
		return errors.New("exactly one of 'value' or 'valuePattern' must be specified")
	}
	if rule.Value == "" && rule.ValuePattern == "" {
		return errors.New("one of 'value' or 'valuePattern' is required")
	}

	// Validate claim is allowed
	if !IsAllowedClaim(rule.Claim) {
		return fmt.Errorf("claim %q is not allowed for matching", rule.Claim)
	}

	return nil
}

// CompileMatchRules compiles a list of MatchRules into a single Matcher.
// Returns an error if any rule is invalid or fails to compile.
func CompileMatchRules(rules []MatchRule) (profile.Matcher, error) {
	matchers := make([]profile.Matcher, 0, len(rules))

	for _, rule := range rules {
		// Validate the rule
		if err := ValidateMatchRule(rule); err != nil {
			return nil, fmt.Errorf("invalid match rule for claim %q: %w", rule.Claim, err)
		}

		// Create appropriate matcher based on rule type
		var matcher profile.Matcher
		var err error

		if rule.Value != "" {
			// Exact match
			matcher = profile.ExactMatcher(rule.Claim, rule.Value)
		} else {
			// Regex match
			matcher, err = profile.RegexMatcher(rule.Claim, rule.ValuePattern)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex pattern for claim %q: %w", rule.Claim, err)
			}
		}

		matchers = append(matchers, matcher)
	}

	// Return composite matcher (handles empty list case)
	return profile.CompositeMatcher(matchers...), nil
}

// IsAllowedClaim checks if a claim is allowed for matching.
// Allowed claims are standard Buildkite JWT claims or agent_tag: prefixed claims.
func IsAllowedClaim(claim string) bool {
	allowedClaims := map[string]bool{
		"pipeline_slug": true,
		"pipeline_id":   true,
		"build_number":  true,
		"build_branch":  true,
		"build_tag":     true,
		"build_commit":  true,
		"cluster_id":    true,
		"cluster_name":  true,
		"queue_id":      true,
		"queue_key":     true,
	}

	if allowedClaims[claim] {
		return true
	}

	// Allow agent_tag: prefix
	if strings.HasPrefix(claim, "agent_tag:") {
		return true
	}

	return false
}

func FetchOrganizationProfile(ctx context.Context, orgProfileLocation string, gh Client) (ProfileConfig, map[string]error, error) {
	profile, failedProfiles, err := LoadProfile(ctx, gh, orgProfileLocation)
	if err != nil {
		return ProfileConfig{}, failedProfiles, err
	}

	return profile, failedProfiles, nil
}

func LoadProfile(ctx context.Context, gh Client, orgProfileLocation string) (ProfileConfig, map[string]error, error) {
	// get the profile
	profile, err := GetProfile(ctx, gh, orgProfileLocation)
	if err != nil {
		return ProfileConfig{}, nil, err
	}

	// validate the profile and compile matchers
	profileConfig, failedProfiles, err := ValidateProfile(ctx, profile)
	if err != nil {
		return ProfileConfig{}, failedProfiles, err
	}

	validCount := len(profileConfig.Organization.Profiles)
	failedCount := len(failedProfiles)
	level := zerolog.InfoLevel
	if failedCount > 0 {
		level = zerolog.WarnLevel
	}

	log.WithLevel(level).
		Str("url", orgProfileLocation).
		Int("valid_profiles", validCount).
		Int("failed_profiles", failedCount).
		Msg("organization profile configuration loaded with validation warnings")

	return profileConfig, failedProfiles, nil
}

func GetProfile(ctx context.Context, gh Client, orgProfileLocation string) (string, error) {
	// get the profile
	owner, repo, path := DecomposePath(orgProfileLocation)
	profile, _, _, err := gh.client.Repositories.GetContents(ctx, owner, repo, path, nil)
	if err != nil {
		return "", fmt.Errorf("organization profile load failed from %s: %w", orgProfileLocation, err)
	}

	return profile.GetContent()
}

func ValidateProfile(ctx context.Context, profile string) (ProfileConfig, map[string]error, error) {
	profileConfig := ProfileConfig{}

	dec := yaml.NewDecoder(strings.NewReader(profile))

	// Loading the profiles MUST fail in the presence of unknown fields otherwise
	// a misconfiguration (like a typo) could lead to unauthorized access through
	// privilege escalation.
	dec.KnownFields(true)

	err := dec.Decode(&profileConfig)
	if err != nil {
		return ProfileConfig{}, nil, fmt.Errorf("organization profile file parsing failed: %w", err)
	}

	// Compile matchers for each profile (graceful degradation)
	validProfiles := make([]Profile, 0, len(profileConfig.Organization.Profiles))
	failedProfiles := make(map[string]error)

	for _, prof := range profileConfig.Organization.Profiles {
		matcher, err := CompileMatchRules(prof.Match)
		if err != nil {
			failedProfiles[prof.Name] = err

			log.Warn().
				Err(err).
				Str("profile", prof.Name).
				Msg("profile validation failed, profile unavailable")
			continue
		}

		// Set compiled matcher
		prof.CompiledMatcher = matcher
		validProfiles = append(validProfiles, prof)
	}

	// Update config with only valid profiles
	profileConfig.Organization.Profiles = validProfiles

	return profileConfig, failedProfiles, nil
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
