package profile

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// compileOrganizationProfiles compiles organization profiles from config.
// Returns a ProfileStoreOf containing valid and invalid profiles.
func compileOrganizationProfiles(profiles []organizationProfile) ProfileStoreOf[OrganizationProfileAttr] {
	validMatchers := make(map[string]Matcher)
	invalidProfiles := make(map[string]error)
	duplicateNameCheck := duplicateNameValidator()

	for _, prof := range profiles {
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

		// Validate repository format
		if err := validateRepositories(prof.Repositories); err != nil {
			invalidProfiles[prof.Name] = fmt.Errorf("invalid repositories: %w", err)
			continue
		}

		// Check for empty permissions list
		if len(prof.Permissions) == 0 {
			err := fmt.Errorf("permissions list must be non-empty")
			invalidProfiles[prof.Name] = err
			continue
		}

		// Validate permissions format
		if err := validatePermissions(prof.Permissions); err != nil {
			invalidProfiles[prof.Name] = fmt.Errorf("invalid permissions: %w", err)
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
	for _, p := range profiles {
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

	return NewProfileStoreOf(validProfiles, invalidProfiles)
}

// compilePipelineProfiles compiles pipeline profiles from config.
// Creates a "default" profile from defaultPermissions.
// Validates that user-defined profiles don't use the reserved "default" name.
// Returns a ProfileStoreOf containing valid and invalid profiles.
func compilePipelineProfiles(profiles []pipelineProfile, defaultPermissions []string) ProfileStoreOf[PipelineProfileAttr] {
	validMatchers := make(map[string]Matcher)
	invalidProfiles := make(map[string]error)
	duplicateNameCheck := duplicateNameValidator()

	for _, prof := range profiles {
		// Check for reserved "default" name
		if prof.Name == "default" {
			err := fmt.Errorf("profile name %q is reserved", "default")
			invalidProfiles[prof.Name] = err
			continue
		}

		// Check for duplicate profile names
		if err := duplicateNameCheck(prof.Name); err != nil {
			invalidProfiles[prof.Name] = err
			continue
		}

		// Check for empty permissions list
		if len(prof.Permissions) == 0 {
			err := fmt.Errorf("permissions list must be non-empty")
			invalidProfiles[prof.Name] = err
			continue
		}

		// Validate permissions format
		if err := validatePermissions(prof.Permissions); err != nil {
			invalidProfiles[prof.Name] = fmt.Errorf("invalid permissions: %w", err)
			continue
		}

		// Compile match rules (empty rules are allowed)
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
			Msg("pipeline profile: some profiles failed validation and were ignored")
	}

	// Build maps for ProfileStoreOf
	validProfiles := make(map[string]AuthorizedProfile[PipelineProfileAttr])

	// Convert valid profiles to AuthorizedProfile format
	for _, p := range profiles {
		matcher, ok := validMatchers[p.Name]
		if !ok {
			// Profile was invalid, skip it
			continue
		}

		attrs := PipelineProfileAttr{
			Permissions: p.Permissions,
		}

		validProfiles[p.Name] = NewAuthorizedProfile(matcher, attrs)
	}

	// Add "default" profile from defaultPermissions
	// Empty match rules means it matches all pipelines
	defaultMatcher, _ := compileMatchRules(nil) // Empty rules always succeed
	validProfiles["default"] = NewAuthorizedProfile(defaultMatcher, PipelineProfileAttr{
		Permissions: defaultPermissions,
	})

	return NewProfileStoreOf(validProfiles, invalidProfiles)
}

// compile transforms profileConfig into runtime Profiles.
// Invalid profiles are tracked in ProfileStoreOf's invalidProfiles map.
// The digest is passed through to the returned Profiles.
// Returns an error if the default pipeline permissions are invalid.
func compile(config profileConfig, digest string, location string) (Profiles, error) {
	// Compile organization profiles
	orgProfiles := compileOrganizationProfiles(config.Organization.Profiles)

	// Extract pipeline defaults with fallback
	pipelineDefaults := config.Pipeline.Defaults.Permissions
	if len(pipelineDefaults) == 0 {
		pipelineDefaults = []string{"contents:read"}
	}

	// Validate pipeline default permissions
	if err := validatePermissions(pipelineDefaults); err != nil {
		return Profiles{}, fmt.Errorf("invalid default permissions for pipeline profiles: %w", err)
	}

	// Compile pipeline profiles
	pipelineProfiles := compilePipelineProfiles(config.Pipeline.Profiles, pipelineDefaults)

	// Create and return Profiles
	return NewProfiles(orgProfiles, pipelineProfiles, digest, location), nil
}

// validatePermissions validates an array of permissions in "field:value" format.
// Returns a combined error containing all validation failures, or nil if all are valid.
func validatePermissions(permissions []string) error {
	var errs []error
	for _, perm := range permissions {
		if err := github.ValidateScope(perm); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// validateRepositories validates that the repositories list follows the required format:
// - If wildcard "*" is present, it must be the only entry
// - Repository names must not contain "/" (no owner prefix)
func validateRepositories(repos []string) error {
	// Check for wildcard mixed with other entries
	hasWildcard := slices.Contains(repos, "*")
	if hasWildcard && len(repos) > 1 {
		return fmt.Errorf("wildcard '*' must be the only repository entry")
	}

	// Check for owner prefix (slash in repo name)
	for _, repo := range repos {
		if repo == "*" {
			continue
		}
		if strings.Contains(repo, "/") {
			return fmt.Errorf("repository %q must not contain owner prefix", repo)
		}
	}
	return nil
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

	// Return composite matcher -- an empty list will always match
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
