package profile

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// compile transforms profileConfig into runtime Profiles.
// Invalid profiles are tracked in ProfileStoreOf's invalidProfiles map.
// The digest is passed through to the returned Profiles.
func compile(config profileConfig, digest string) Profiles {
	// Compile matchers for each profile (graceful degradation)
	validMatchers := make(map[string]Matcher)
	invalidProfiles := make(map[string]error)
	duplicateNameCheck := duplicateNameValidator()

	for _, prof := range config.Organization.Profiles {
		// Check for duplicate profile names
		if err := duplicateNameCheck(prof.Name); err != nil {
			invalidProfiles[prof.Name] = err
			continue
		}

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

		matcher, err := compileMatchRules(prof.Match)
		if err != nil {
			invalidProfiles[prof.Name] = err
			continue
		}

		validMatchers[prof.Name] = matcher
	}

	// Log warnings for invalid profiles
	if len(invalidProfiles) > 0 {
		d := zerolog.Dict()
		for name, err := range invalidProfiles {
			d.Str(name, err.Error())
		}

		log.Warn().
			Dict("invalid_profiles", d).
			Msg("organization profile: some profiles failed validation and were ignored")
	}

	// Build maps for ProfileStoreOf
	validProfiles := make(map[string]AuthorizedProfile[OrganizationProfileAttr])

	// Convert valid profiles to AuthorizedProfile format
	for _, p := range config.Organization.Profiles {
		matcher, ok := validMatchers[p.Name]
		if !ok {
			// Profile was invalid, skip it
			continue
		}

		attrs := OrganizationProfileAttr{
			Repositories: p.Repositories,
			Permissions:  p.Permissions,
		}

		validProfiles[p.Name] = NewAuthorizedProfile(matcher, attrs)
	}

	// Create ProfileStoreOf
	orgProfiles := NewProfileStoreOf(validProfiles, invalidProfiles)

	// Extract pipeline defaults with fallback
	pipelineDefaults := config.Organization.Defaults.Permissions
	if len(pipelineDefaults) == 0 {
		pipelineDefaults = []string{"contents:read"}
	}

	// Create and return Profiles
	return NewProfiles(orgProfiles, pipelineDefaults, digest)
}

// duplicateNameValidator creates a validator function that checks for duplicate profile names.
func duplicateNameValidator() func(string) error {
	seenNames := make(map[string]struct{})

	return func(name string) error {
		if _, exists := seenNames[name]; exists {
			return fmt.Errorf("duplicate profile name: %q", name)
		}
		seenNames[name] = struct{}{}
		return nil
	}
}

// validateMatchRule validates that a match rule is well-formed:
// - Exactly one of value or valuePattern must be specified
// - The claim must be in the allowed list
func validateMatchRule(rule matchRule) error {
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

// compileMatchRules compiles a list of matchRules into a single Matcher.
// Returns an error if any rule is invalid or fails to compile.
func compileMatchRules(rules []matchRule) (Matcher, error) {
	matchers := make([]Matcher, 0, len(rules))

	for _, rule := range rules {
		// Validate the rule
		if err := validateMatchRule(rule); err != nil {
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
