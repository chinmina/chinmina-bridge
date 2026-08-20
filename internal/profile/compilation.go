package profile

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"log/slog"

	"github.com/chinmina/chinmina-bridge/internal/github"
)

const (
	// LiteralCallerScoped is the YAML literal for caller-supplied repository scoping.
	LiteralCallerScoped = "{{caller-scoped-repository}}"
	// LiteralAllRepositories is the YAML literal for all-repositories access.
	LiteralAllRepositories = "{{all-repositories}}"
	// LiteralDeprecatedWildcard is the deprecated "*" wildcard, retained as an
	// alias for LiteralAllRepositories until it is removed in version 1.
	LiteralDeprecatedWildcard = "*"
)

// resolveRepositoryScope converts a raw repositories list into a typed RepositoryScope.
// This is called after validation, so the input is known to be well-formed.
func resolveRepositoryScope(repos []string) RepositoryScope {
	if len(repos) == 1 {
		switch repos[0] {
		case LiteralCallerScoped:
			return NewCallerScopedScope()
		case LiteralAllRepositories, LiteralDeprecatedWildcard:
			return NewWildcardScope()
		}
	}
	return NewSpecificScope(repos...)
}

// AppLookup reports whether a profile may name this app: registered, and
// enabled. It is the registry's own resolution function, so compiled profiles
// and live requests cannot disagree about which apps are usable.
type AppLookup func(name string) bool

// DefaultAppOnly is the lookup for deployments with no app registry, and for
// compilation outside a running service: only the default app is usable.
func DefaultAppOnly(name string) bool {
	return name == github.DefaultAppName
}

// resolveProfileApp normalises and validates a profile's declared app. An
// omitted `app` and an explicit `app: default` produce the same value, so a
// valid profile's app name is never empty and the resolver can treat an empty
// one as a defect.
func resolveProfileApp(app *string, usable AppLookup) (string, error) {
	if app == nil {
		return github.DefaultAppName, nil
	}

	if *app == "" {
		return "", fmt.Errorf("app must not be empty")
	}

	if !usable(*app) {
		return "", fmt.Errorf("app %q is not a configured, enabled application", *app)
	}

	return *app, nil
}

// appNameValidator resolves a profile's declared app (nil meaning "default")
// to the name its tokens mint through, or explains why it can't. It is
// resolveProfileApp curried with the registry's usability check, so
// compileProfile itself carries no registry-shaped dependency — only a
// function from "declared app" to "resolved name or error".
type appNameValidator func(app *string) (string, error)

func newAppNameValidator(usable AppLookup) appNameValidator {
	return func(app *string) (string, error) {
		return resolveProfileApp(app, usable)
	}
}

// compileOrganizationProfile compiles one profile in isolation: it either
// produces a complete AuthorizedProfile, or fails, so no attribute of the
// result can come from a different configuration entry.
func compileOrganizationProfile(
	prof organizationProfile,
	checkDuplicate duplicateNameValidator,
	checkAppName appNameValidator,
) (AuthorizedProfile[OrganizationProfileAttr], error) {
	if err := checkDuplicate(prof.Name); err != nil {
		return AuthorizedProfile[OrganizationProfileAttr]{}, err
	}

	// Reject names that would produce an ambiguous URN
	if err := validateProfileName(prof.Name); err != nil {
		return AuthorizedProfile[OrganizationProfileAttr]{}, err
	}

	if len(prof.Repositories) == 0 {
		return AuthorizedProfile[OrganizationProfileAttr]{}, fmt.Errorf("repositories list must be non-empty")
	}

	if err := validateRepositories(prof.Repositories); err != nil {
		return AuthorizedProfile[OrganizationProfileAttr]{}, fmt.Errorf("invalid repositories: %w", err)
	}

	if len(prof.Permissions) == 0 {
		return AuthorizedProfile[OrganizationProfileAttr]{}, fmt.Errorf("permissions list must be non-empty")
	}

	if err := validatePermissions(prof.Permissions); err != nil {
		return AuthorizedProfile[OrganizationProfileAttr]{}, fmt.Errorf("invalid permissions: %w", err)
	}

	app, err := checkAppName(prof.App)
	if err != nil {
		return AuthorizedProfile[OrganizationProfileAttr]{}, err
	}

	matcher, err := compileMatchRules(prof.Match)
	if err != nil {
		return AuthorizedProfile[OrganizationProfileAttr]{}, err
	}

	// Emit deprecation warning for "*" wildcard
	if len(prof.Repositories) == 1 && prof.Repositories[0] == LiteralDeprecatedWildcard {
		slog.Warn("organization profile: '*' is deprecated, use '{{all-repositories}}' instead",
			"profile", prof.Name,
		)
	}

	attrs := OrganizationProfileAttr{
		Scope:       resolveRepositoryScope(prof.Repositories),
		Permissions: ensureMetadataRead(prof.Permissions),
		App:         app,
	}

	return NewAuthorizedProfile(matcher, attrs), nil
}

// compileOrganizationProfiles compiles organization profiles from config.
// Returns a ProfileStoreOf containing valid and invalid profiles.
func compileOrganizationProfiles(profiles []organizationProfile, usableApp AppLookup) ProfileStoreOf[OrganizationProfileAttr] {
	validProfiles := make(map[string]AuthorizedProfile[OrganizationProfileAttr])
	invalidProfiles := make(map[string]error)
	checkDuplicate := newDuplicateNameValidator()
	checkAppName := newAppNameValidator(usableApp)

	for _, prof := range profiles {
		compiled, err := compileOrganizationProfile(prof, checkDuplicate, checkAppName)
		if err != nil {
			invalidProfiles[prof.Name] = err
			continue
		}

		validProfiles[prof.Name] = compiled
	}

	logInvalidProfiles("organization", invalidProfiles)

	return NewProfileStoreOf(validProfiles, invalidProfiles)
}

// logInvalidProfiles reports the profiles that failed validation, so an
// operator sees the rejections that a successful load would otherwise hide.
func logInvalidProfiles(kind string, invalidProfiles map[string]error) {
	if len(invalidProfiles) == 0 {
		return
	}

	attrs := make([]slog.Attr, 0, len(invalidProfiles))
	for name, err := range invalidProfiles {
		attrs = append(attrs, slog.String(name, err.Error()))
	}

	slog.Warn(kind+" profile: some profiles failed validation and were ignored",
		slog.Attr{Key: "invalid_profiles", Value: slog.GroupValue(attrs...)})
}

// compilePipelineProfile compiles one profile in isolation. As for
// organization profiles, the result is either complete or absent.
func compilePipelineProfile(
	prof pipelineProfile,
	checkDuplicate duplicateNameValidator,
	checkAppName appNameValidator,
) (AuthorizedProfile[PipelineProfileAttr], error) {
	// Check for reserved "default" name
	if prof.Name == "default" {
		return AuthorizedProfile[PipelineProfileAttr]{}, fmt.Errorf("profile name %q is reserved", "default")
	}

	if err := checkDuplicate(prof.Name); err != nil {
		return AuthorizedProfile[PipelineProfileAttr]{}, err
	}

	// Reject names that would produce an ambiguous URN
	if err := validateProfileName(prof.Name); err != nil {
		return AuthorizedProfile[PipelineProfileAttr]{}, err
	}

	if len(prof.Permissions) == 0 {
		return AuthorizedProfile[PipelineProfileAttr]{}, fmt.Errorf("permissions list must be non-empty")
	}

	if err := validatePermissions(prof.Permissions); err != nil {
		return AuthorizedProfile[PipelineProfileAttr]{}, fmt.Errorf("invalid permissions: %w", err)
	}

	app, err := checkAppName(prof.App)
	if err != nil {
		return AuthorizedProfile[PipelineProfileAttr]{}, err
	}

	// Compile match rules (empty rules are allowed)
	matcher, err := compileMatchRules(prof.Match)
	if err != nil {
		return AuthorizedProfile[PipelineProfileAttr]{}, err
	}

	attrs := PipelineProfileAttr{
		Permissions: ensureMetadataRead(prof.Permissions),
		App:         app,
	}

	return NewAuthorizedProfile(matcher, attrs), nil
}

// compilePipelineProfiles compiles pipeline profiles from config.
// Creates a "default" profile from defaultPermissions.
// Validates that user-defined profiles don't use the reserved "default" name.
// Returns a ProfileStoreOf containing valid and invalid profiles.
func compilePipelineProfiles(profiles []pipelineProfile, defaultPermissions []string, usableApp AppLookup) ProfileStoreOf[PipelineProfileAttr] {
	validProfiles := make(map[string]AuthorizedProfile[PipelineProfileAttr])
	invalidProfiles := make(map[string]error)
	checkDuplicate := newDuplicateNameValidator()
	checkAppName := newAppNameValidator(usableApp)

	for _, prof := range profiles {
		compiled, err := compilePipelineProfile(prof, checkDuplicate, checkAppName)
		if err != nil {
			invalidProfiles[prof.Name] = err
			continue
		}

		validProfiles[prof.Name] = compiled
	}

	logInvalidProfiles("pipeline", invalidProfiles)

	// Add "default" profile from defaultPermissions
	// Empty match rules means it matches all pipelines
	// Always the default app: it is synthesised, so there is no YAML to name
	// one, and the reserved name prevents a declared override.
	defaultMatcher, _ := compileMatchRules(nil) // Empty rules always succeed
	validProfiles["default"] = NewAuthorizedProfile(defaultMatcher, PipelineProfileAttr{
		Permissions: ensureMetadataRead(defaultPermissions),
		App:         github.DefaultAppName,
	})

	return NewProfileStoreOf(validProfiles, invalidProfiles)
}

// compile transforms profileConfig into runtime Profiles.
// Invalid profiles are tracked in ProfileStoreOf's invalidProfiles map.
// The digest is passed through to the returned Profiles.
// Returns an error if the default pipeline permissions are invalid.
//
// Validity depends on the registry as well as the YAML: a profile naming an
// app that usableApp rejects is compiled as invalid.
func compile(config profileConfig, digest string, location string, usableApp AppLookup) (Profiles, error) {
	// Compile organization profiles
	orgProfiles := compileOrganizationProfiles(config.Organization.Profiles, usableApp)

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
	pipelineProfiles := compilePipelineProfiles(config.Pipeline.Profiles, pipelineDefaults, usableApp)

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

// ensureMetadataRead ensures metadata:read is always present in permissions.
// This mirrors fine-grained token behavior and reduces surprises when using
// tokens with the REST API.
func ensureMetadataRead(permissions []string) []string {
	const metadataRead = "metadata:read"
	if slices.Contains(permissions, metadataRead) {
		return permissions
	}
	return append(permissions, metadataRead)
}

// validateProfileName rejects profile names containing characters that would
// produce an ambiguous profile URN. '/' is the URN path separator and ':' is
// the ShortString type prefix separator (see ProfileRef.String/ShortString),
// so a name containing either could not be represented or round-tripped
// unambiguously — and a '/' in particular would inject extra segments into the
// cache-key URN.
func validateProfileName(name string) error {
	if strings.ContainsAny(name, "/:") {
		return fmt.Errorf("profile name %q must not contain '/' or ':'", name)
	}
	return nil
}

// validateRepositories validates that the repositories list follows the required format:
// - If a literal ({{caller-scoped-repository}}, {{all-repositories}}, or "*") is present, it must be the only entry
// - Repository names must not contain "/" (no owner prefix)
func validateRepositories(repos []string) error {
	for _, repo := range repos {
		switch repo {
		case LiteralCallerScoped, LiteralAllRepositories, LiteralDeprecatedWildcard:
			if len(repos) > 1 {
				return fmt.Errorf("%q must be the only repository entry", repo)
			}
			return nil
		}
	}

	// Static repo names: check for owner prefix (slash)
	for _, repo := range repos {
		if strings.Contains(repo, "/") {
			return fmt.Errorf("repository %q must not contain owner prefix", repo)
		}
	}
	return nil
}

// duplicateNameValidator rejects a profile name already seen by an earlier
// call, so a second entry sharing a name never reaches the maps a first entry
// already populated.
type duplicateNameValidator func(name string) error

func newDuplicateNameValidator() duplicateNameValidator {
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
