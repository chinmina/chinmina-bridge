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

// compile transforms profileConfig into runtime Profiles. A profile naming an
// app the registry has not authorised is compiled as invalid rather than
// failing the whole load.
func compile(config profileConfig, digest string, location string, usableApp AppLookup) (Profiles, error) {
	orgProfiles := compileOrganizationProfiles(config.Organization.Profiles, usableApp)

	pipelineDefaults := config.Pipeline.Defaults.Permissions
	if len(pipelineDefaults) == 0 {
		pipelineDefaults = []string{"contents:read"}
	}

	if err := validatePermissions(pipelineDefaults); err != nil {
		return Profiles{}, fmt.Errorf("invalid default permissions for pipeline profiles: %w", err)
	}

	pipelineProfiles := compilePipelineProfiles(config.Pipeline.Profiles, pipelineDefaults, usableApp)

	return NewProfiles(orgProfiles, pipelineProfiles, digest, location), nil
}

// compileOrganizationProfiles validates and compiles every organization
// profile, discarding invalid ones rather than failing the whole load.
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

// compilePipelineProfiles validates and compiles every pipeline profile, then
// appends the synthesised "default" profile that always mints through the
// default app.
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

	// Always the default app: it is synthesised, so there is no YAML to name
	// one, and the reserved name prevents a declared override.
	defaultMatcher, _ := compileMatchRules(nil) // Empty rules always succeed
	validProfiles[ProfileNameDefault] = NewAuthorizedProfile(defaultMatcher, PipelineProfileAttr{
		Permissions: ensureMetadataRead(defaultPermissions),
		App:         github.DefaultAppName,
	})

	return NewProfileStoreOf(validProfiles, invalidProfiles)
}

// compilePipelineProfile compiles one profile in isolation. As for
// organization profiles, the result is either complete or absent.
func compilePipelineProfile(
	prof pipelineProfile,
	checkDuplicate duplicateNameValidator,
	checkAppName appNameValidator,
) (AuthorizedProfile[PipelineProfileAttr], error) {
	if prof.Name == ProfileNameDefault {
		return AuthorizedProfile[PipelineProfileAttr]{}, fmt.Errorf("profile name %q is reserved", ProfileNameDefault)
	}

	if err := checkDuplicate(prof.Name); err != nil {
		return AuthorizedProfile[PipelineProfileAttr]{}, err
	}

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

// appNameValidator resolves a profile's declared app to the name its tokens
// mint through. It keeps compileOrganizationProfile/compilePipelineProfile
// independent of registry lookups.
type appNameValidator func(app *string) (string, error)

func newAppNameValidator(usable AppLookup) appNameValidator {
	return func(app *string) (string, error) {
		return resolveProfileApp(app, usable)
	}
}

// duplicateNameValidator rejects a profile name already seen by an earlier
// call, so a second entry sharing a name is rejected outright rather than
// contributing any of its attributes to the first.
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

// resolveRepositoryScope converts a raw repositories list into a typed
// RepositoryScope. Called only after validation, so the input is known to be
// well-formed.
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

// validateProfileName rejects profile names containing characters that would
// produce an ambiguous profile URN: '/' is the URN path separator and ':' is
// the ShortString type prefix separator (see ProfileRef.String/ShortString).
func validateProfileName(name string) error {
	if strings.ContainsAny(name, "/:") {
		return fmt.Errorf("profile name %q must not contain '/' or ':'", name)
	}
	return nil
}

// validateRepositories rejects a repositories list that mixes a literal
// (e.g. {{all-repositories}}) with other entries, or names a repository with
// an owner prefix.
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

	for _, repo := range repos {
		if strings.Contains(repo, "/") {
			return fmt.Errorf("repository %q must not contain owner prefix", repo)
		}
	}
	return nil
}

// validatePermissions checks that every permission is in "field:value"
// format, collecting all failures into one combined error.
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

// validateMatchRule rejects a rule that doesn't specify exactly one of
// value/valuePattern, or names a claim outside the allowed list.
func validateMatchRule(rule matchRule) error {
	if rule.Value != "" && rule.ValuePattern != "" {
		return errors.New("exactly one of 'value' or 'valuePattern' must be specified")
	}
	if rule.Value == "" && rule.ValuePattern == "" {
		return errors.New("one of 'value' or 'valuePattern' is required")
	}

	if !IsAllowedClaim(rule.Claim) {
		return fmt.Errorf("claim %q is not allowed for matching", rule.Claim)
	}

	return nil
}

// compileMatchRules compiles a list of matchRules into a single Matcher,
// failing if any rule is invalid or its pattern won't compile. An empty rule
// list always matches.
func compileMatchRules(rules []matchRule) (Matcher, error) {
	matchers := make([]Matcher, 0, len(rules))

	for _, rule := range rules {
		if err := validateMatchRule(rule); err != nil {
			return nil, fmt.Errorf("invalid match rule for claim %q: %w", rule.Claim, err)
		}

		var matcher Matcher
		var err error

		if rule.Value != "" {
			matcher = ExactMatcher(rule.Claim, rule.Value)
		} else {
			matcher, err = RegexMatcher(rule.Claim, rule.ValuePattern)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex pattern for claim %q: %w", rule.Claim, err)
			}
		}

		matchers = append(matchers, matcher)
	}

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

// IsAllowedClaim checks if a claim is allowed for matching. Allowed claims
// are standard Buildkite JWT claims or agent_tag: prefixed claims.
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
