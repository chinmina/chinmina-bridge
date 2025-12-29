package profile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// Sentinel errors for matching
var (
	// ErrNoMatch indicates that profile match conditions were not satisfied
	ErrNoMatch = errors.New("profile match conditions not met")
)

// ClaimValidationError indicates a claim value failed validation
type ClaimValidationError struct {
	Claim string
	Value string
	Err   error
}

func (e ClaimValidationError) Error() string {
	return fmt.Sprintf("claim %q validation failed for value %q: %v", e.Claim, e.Value, e.Err)
}

func (e ClaimValidationError) Unwrap() error {
	return e.Err
}

func (e ClaimValidationError) Status() (int, string) {
	return http.StatusForbidden, http.StatusText(http.StatusForbidden)
}

type ProfileConfig struct {
	Organization struct {
		Defaults struct {
			Permissions []string `yaml:"permissions"`
		} `yaml:"defaults"`
		Profiles        []Profile        `yaml:"profiles"`
		InvalidProfiles map[string]error `yaml:"-"`
	} `yaml:"organization"`

	// digest is the SHA256 hash of the source YAML content.
	// Populated during profile loading, not from YAML.
	digest string `yaml:"-"`
}

// Digest returns the SHA256 hash of the source YAML content used to create
// this ProfileConfig.
func (config ProfileConfig) Digest() string {
	return config.digest
}

func (p ProfileConfig) MarshalZerologObject(e *zerolog.Event) {
	result, err := json.Marshal(p)
	if err != nil {
		err = fmt.Errorf("failed to marshal ProfileConfig: %w", err)
		e.Err(err)
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

type Profile struct {
	Name         string      `yaml:"name"`
	Match        []MatchRule `yaml:"match"`
	Repositories []string    `yaml:"repositories"`
	Permissions  []string    `yaml:"permissions"`

	// compiledMatcher is the compiled matcher from Match rules.
	// Populated during profile loading, not from YAML.
	compiledMatcher Matcher `yaml:"-"`
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

func (e ProfileUnavailableError) Error() string {
	return fmt.Sprintf("profile %q unavailable: validation failed", e.Name)
}

func (e ProfileUnavailableError) Unwrap() error {
	return e.Cause
}

func (e ProfileUnavailableError) Status() (int, string) {
	return http.StatusNotFound, "profile unavailable: validation failed"
}

// ProfileNotFoundError indicates a profile was not found in the store
type ProfileNotFoundError struct {
	Name string
}

func (e ProfileNotFoundError) Error() string {
	return fmt.Sprintf("profile %q not found", e.Name)
}

func (e ProfileNotFoundError) Status() (int, string) {
	return http.StatusNotFound, "profile not found"
}

// ProfileMatchFailedError indicates a profile's match conditions were not met
type ProfileMatchFailedError struct {
	Name string
}

func (e ProfileMatchFailedError) Error() string {
	return fmt.Sprintf("profile %q match conditions not met", e.Name)
}

func (e ProfileMatchFailedError) Status() (int, string) {
	return http.StatusForbidden, http.StatusText(http.StatusForbidden)
}

// ProfileStoreNotLoadedError indicates the profile store has not been loaded
type ProfileStoreNotLoadedError struct{}

func (e ProfileStoreNotLoadedError) Error() string {
	return "organization profile not loaded"
}

func (e ProfileStoreNotLoadedError) Status() (int, string) {
	return http.StatusServiceUnavailable, "organization profile not loaded"
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

	// Validate claim name is allowed and valid
	if !IsAllowedClaim(rule.Claim) {
		return fmt.Errorf("claim %q is not allowed for matching", rule.Claim)
	}

	return nil
}

// CompileMatchRules compiles a list of MatchRules into a single Matcher.
// Returns an error if any rule is invalid or fails to compile.
func CompileMatchRules(rules []MatchRule) (Matcher, error) {
	matchers := make([]Matcher, 0, len(rules))

	for _, rule := range rules {
		// Validate the rule
		if err := ValidateMatchRule(rule); err != nil {
			return nil, fmt.Errorf("invalid match rule for claim %q: %w", rule.Claim, err)
		}

		// Create appropriate matcher based on rule type
		var matcher Matcher
		var err error

		if rule.Value != "" {
			// Exact match
			matcher = ExactMatcher(rule.Claim, rule.Value)
		} else {
			// Regex match
			matcher, err = RegexMatcher(rule.Claim, rule.ValuePattern)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex pattern for claim %q: %w", rule.Claim, err)
			}
		}

		matchers = append(matchers, matcher)
	}

	// Return composite matcher (handles empty list case)
	return CompositeMatcher(matchers...), nil
}

var allowedClaims = map[string]bool{
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

// IsAllowedClaim checks if a claim is allowed for matching.
// Allowed claims are standard Buildkite JWT claims or agent_tag: prefixed claims.
func IsAllowedClaim(claim string) bool {

	if allowedClaims[claim] {
		return true
	}

	// Allow agent_tag: prefix, but make sure control or whitespace characters
	// don't creep in and cause havoc
	if strings.HasPrefix(claim, "agent_tag:") && IsValidClaimPart(claim) {
		return true
	}

	return false
}

func FetchOrganizationProfile(ctx context.Context, orgProfileLocation string, gh github.Client) (Profiles, error) {
	profiles, err := LoadProfile(ctx, gh, orgProfileLocation)
	if err != nil {
		return Profiles{}, err
	}

	return profiles, nil
}

func LoadProfile(ctx context.Context, gh github.Client, orgProfileLocation string) (Profiles, error) {
	// get the profile
	profile, err := GetProfile(ctx, gh, orgProfileLocation)
	if err != nil {
		return Profiles{}, err
	}

	// validate the profile and compile matchers
	profileConfig, err := ValidateProfile(ctx, profile)
	if err != nil {
		return Profiles{}, err
	}

	validCount := len(profileConfig.Organization.Profiles)
	invalidCount := len(profileConfig.Organization.InvalidProfiles)
	level := zerolog.InfoLevel
	if invalidCount > 0 {
		level = zerolog.WarnLevel
	}

	log.WithLevel(level).
		Str("url", orgProfileLocation).
		Int("valid_profiles", validCount).
		Int("invalid_profiles", invalidCount).
		Msg("loaded organization profile configuration")

	// Compile to runtime format
	return CompileProfiles(profileConfig), nil
}

func GetProfile(ctx context.Context, gh github.Client, orgProfileLocation string) (string, error) {
	// get the profile
	owner, repo, path := DecomposePath(orgProfileLocation)
	profile, err := gh.GetFileContent(ctx, owner, repo, path)
	if err != nil {
		return "", fmt.Errorf("organization profile load failed from %s: %w", orgProfileLocation, err)
	}

	return profile, nil
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
		return ProfileConfig{}, fmt.Errorf("organization profile file parsing failed: %w", err)
	}

	// Calculate SHA256 digest of the source YAML for change detection
	hash := sha256.Sum256([]byte(profile))
	digest := hex.EncodeToString(hash[:])

	// Compile matchers for each profile (graceful degradation)
	validProfiles := make([]Profile, 0, len(profileConfig.Organization.Profiles))
	invalidProfiles := make(map[string]error)
	seenNames := make(map[string]bool)

	for _, prof := range profileConfig.Organization.Profiles {
		// Check for duplicate profile names
		if seenNames[prof.Name] {
			err := fmt.Errorf("duplicate profile name: %q", prof.Name)
			invalidProfiles[prof.Name] = err
			continue
		}
		seenNames[prof.Name] = true

		// Check for empty repositories list
		if len(prof.Repositories) == 0 {
			err := fmt.Errorf("repositories list must be non-empty")
			invalidProfiles[prof.Name] = err
			continue
		}

		// Check for empty permissions list
		if len(prof.Permissions) == 0 {
			err := fmt.Errorf("permissions list must be non-empty")
			invalidProfiles[prof.Name] = err
			continue
		}

		matcher, err := CompileMatchRules(prof.Match)
		if err != nil {
			invalidProfiles[prof.Name] = err
			continue
		}

		// Set compiled matcher
		prof.compiledMatcher = matcher
		validProfiles = append(validProfiles, prof)
	}

	// Update config with only valid profiles and set digest
	profileConfig.Organization.Profiles = validProfiles
	profileConfig.Organization.InvalidProfiles = invalidProfiles
	profileConfig.digest = digest

	if len(invalidProfiles) > 0 {
		d := zerolog.Dict()
		for name, err := range invalidProfiles {
			d.Str(name, err.Error())
		}

		log.Warn().
			Dict("invalid_profiles", d).
			Msg("organization profile: some profiles failed validation and were ignored")
	}

	return profileConfig, nil
}

// DecomposePath into the owner, repo, and path (no http prefix), assuming the
// location is in the format owner:repo:path_seg1/path_seg2/...
func DecomposePath(profileLocation string) (string, string, string) {
	// e.g.: "cultureamp:chinmina:docs/profile.yaml"
	location := strings.SplitN(profileLocation, ":", 3)

	if len(location) != 3 {
		return "", "", ""
	}

	orgName, repoName, filePath := location[0], location[1], location[2]

	return orgName, repoName, filePath
}

// NewTestProfile creates a Profile for testing with an empty compiled matcher.
// This is only for use in tests where you need to construct profiles directly.
func NewTestProfile(name string, repositories []string, permissions []string) Profile {
	return Profile{
		Name:            name,
		Match:           []MatchRule{},
		Repositories:    repositories,
		Permissions:     permissions,
		compiledMatcher: CompositeMatcher(), // Empty matcher for testing
	}
}

// NewTestProfileConfig creates a ProfileConfig for testing with the given profiles.
// This is only for use in tests where you need to construct profile configs directly.
func NewTestProfileConfig(profiles ...Profile) ProfileConfig {
	return ProfileConfig{
		Organization: struct {
			Defaults struct {
				Permissions []string `yaml:"permissions"`
			} `yaml:"defaults"`
			Profiles        []Profile        `yaml:"profiles"`
			InvalidProfiles map[string]error `yaml:"-"`
		}{
			Defaults: struct {
				Permissions []string `yaml:"permissions"`
			}{
				Permissions: []string{"contents:read"},
			},
			Profiles:        profiles,
			InvalidProfiles: make(map[string]error),
		},
		digest: rand.Text(), // random digest to make sure each config is considered unique
	}
}

// CompileProfiles converts a ProfileConfig (serialization format) into Profiles (runtime format).
// It transforms Profile structs into AuthorizedProfile instances with matcher closures,
// extracts default permissions, and preserves invalid profile information.
func CompileProfiles(config ProfileConfig) Profiles {
	// Build maps for ProfileStoreOf
	validProfiles := make(map[string]AuthorizedProfile[OrganizationProfileAttr])
	invalidProfiles := make(map[string]error)

	// Convert valid profiles to AuthorizedProfile format
	for _, p := range config.Organization.Profiles {
		attrs := OrganizationProfileAttr{
			Repositories: p.Repositories,
			Permissions:  p.Permissions,
		}

		validProfiles[p.Name] = NewAuthorizedProfile(p.compiledMatcher, attrs)
	}

	// Copy invalid profiles
	maps.Copy(invalidProfiles, config.Organization.InvalidProfiles)

	// Create ProfileStoreOf
	orgProfiles := NewProfileStoreOf(validProfiles, invalidProfiles)

	// Extract pipeline defaults
	pipelineDefaults := config.GetDefaultPermissions()

	// Create and return Profiles
	return NewProfiles(orgProfiles, pipelineDefaults, config.Digest())
}
