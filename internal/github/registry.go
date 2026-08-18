package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	appconfig "github.com/chinmina/chinmina-bridge/internal/config"
)

// DefaultAppName is the reserved name of the app configured by the
// GITHUB_APP_* variables. A profile may name it explicitly; omitting the app
// property resolves to the same identity.
const DefaultAppName = "default"

// maxAppNameLength bounds a registry entry's name. Names appear in log lines,
// audit entries and metric attributes, so an unbounded one is an unbounded
// cardinality and an unbounded log record.
const maxAppNameLength = 64

// appNamePattern constrains a registry entry's name to a lower-case,
// URL- and label-safe form. Names travel into metric attributes and audit
// entries, so the set of accepted characters is deliberately small.
var appNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// ErrPrivateKeyInvalid reports an unparseable private key.
//
// This is a deliberate, documented exception to the project's %w-wrapping
// convention. The underlying error comes from a third-party parser whose
// message content is outside our control and may change on any dependency
// bump; a configuration error must never carry a substring of the key it
// failed to parse. The entry is identified by name, and the operator has the
// key — the library's message adds nothing they cannot reproduce.
var ErrPrivateKeyInvalid = errors.New("private key could not be parsed")

// ErrAppUnknown reports a name that resolves to no usable app. A disabled app
// is indistinguishable from an absent one here by design: enabled state is
// exposed for logging only, so no caller can resolve a disabled app by
// forgetting to check a flag.
var ErrAppUnknown = errors.New("no such app")

// AppIdentity is what a profile's app name resolves to: enough to mint through
// an installation and to attribute the result, and nothing else. It is plain
// data rather than a client or a closure, so it can travel on the resolved
// request value and into a cache key without carrying a credential with it.
type AppIdentity struct {
	Name           string
	ApplicationID  int64
	InstallationID int64
}

// IsZero reports whether the identity was never resolved. Callers that key on
// an identity use this to refuse rather than silently key on zeroes.
func (i AppIdentity) IsZero() bool {
	return i == AppIdentity{}
}

// LogValue keeps the identity's log shape fixed at the three fields that
// identify it. Key material never reaches this type, so there is nothing to
// redact.
func (i AppIdentity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", i.Name),
		slog.Int64("applicationID", i.ApplicationID),
		slog.Int64("installationID", i.InstallationID),
	)
}

// appEntryConfig is one GITHUB_APPS entry as configured. It is the only type
// in the registry that holds key material, and its LogValue omits it: an
// operator cannot leak a key by logging this value, whatever they add to the
// struct later.
type appEntryConfig struct {
	Name           string `json:"name"`
	ApplicationID  int64  `json:"appId"`
	InstallationID int64  `json:"installationId"`
	PrivateKey     string `json:"privateKey"`
	PrivateKeyARN  string `json:"privateKeyArn"`
}

// keySource names where a key comes from without disclosing it. Exactly one
// source is present by the time this is called.
func keySource(privateKeyARN string) string {
	if privateKeyARN != "" {
		return "privateKeyArn"
	}
	return "privateKey"
}

// LogValue deliberately omits PrivateKey and PrivateKeyARN. The ARN is
// omitted as well as the key: it names the credential and its account, and an
// operator reading a log has no use for it that justifies publishing it.
func (e appEntryConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", e.Name),
		slog.Int64("applicationID", e.ApplicationID),
		slog.Int64("installationID", e.InstallationID),
		slog.String("keySource", keySource(e.PrivateKeyARN)),
	)
}

// resolvedApp is a registry entry after verification. It holds no key
// material: the client it wraps has already absorbed the key, so nothing that
// survives construction can disclose one.
type resolvedApp struct {
	identity  AppIdentity
	client    Client
	keySource string

	// enabled is false for an app on a different account, or one whose
	// installation could not be queried. Disabled is terminal until the
	// process restarts: re-verification would make an instance's enabled set a
	// function of when its timer fired rather than of its configuration.
	enabled bool

	// accountLogin is the verified organization, for logging. Empty when
	// verification failed.
	accountLogin string

	// disabledReason explains a false enabled, for the startup log only.
	disabledReason string
}

// LogValue is the R48 startup record: name, application ID, installation ID,
// verified organization and enabled state.
func (a resolvedApp) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("name", a.identity.Name),
		slog.Int64("applicationID", a.identity.ApplicationID),
		slog.Int64("installationID", a.identity.InstallationID),
		slog.String("keySource", a.keySource),
		slog.String("organization", a.accountLogin),
		slog.Bool("enabled", a.enabled),
	}
	if a.disabledReason != "" {
		attrs = append(attrs, slog.String("disabledReason", a.disabledReason))
	}
	return slog.GroupValue(attrs...)
}

// Registry maps a profile's app name to the installation its tokens are minted
// through. It is built once at startup and never written afterwards: methods
// take value receivers over a map that the constructor is the only writer of,
// so a handler that captured it cannot observe it change, and no request path
// needs a lock.
//
// The default app is always present under DefaultAppName, whether or not
// GITHUB_APPS is configured.
type Registry struct {
	apps map[string]resolvedApp
}

// NewRegistry builds the app registry from the default app's configuration and
// the GITHUB_APPS entries alongside it.
//
// ctx must be the long-lived server context. It reaches KMS-backed signing key
// construction, and a key built under a startup- or verification-scoped
// context would boot cleanly and then fail every mint once that context
// expired.
//
// defaultClient is the already-constructed client for the default app, reused
// rather than rebuilt so the default app has exactly one minting identity.
//
// Errors here are deploy-blocking and deterministic: they describe
// configuration with no single unambiguous meaning, or a default app that
// cannot authenticate as itself. An individual registry app that cannot be
// verified is disabled instead, so one unreachable credential does not take
// down vending for every other profile.
func NewRegistry(ctx context.Context, cfg appconfig.GithubConfig, defaultClient Client) (Registry, error) {
	defaultApp := resolvedApp{
		identity: AppIdentity{
			Name:           DefaultAppName,
			ApplicationID:  cfg.ApplicationID,
			InstallationID: cfg.InstallationID,
		},
		client:    defaultClient,
		keySource: keySource(cfg.PrivateKeyARN),
		enabled:   true,
	}

	entries, err := parseAppEntries(cfg.Apps)
	if err != nil {
		return Registry{}, err
	}

	// R19: with no registry configured the default app vends everything and
	// startup queries no installation at all. Deployments not using the
	// feature pay nothing for its existence.
	if len(entries) == 0 {
		return Registry{apps: map[string]resolvedApp{DefaultAppName: defaultApp}}, nil
	}

	loadAWS := newAWSConfigLoader(ctx)

	apps := make(map[string]resolvedApp, len(entries)+1)
	apps[DefaultAppName] = defaultApp

	for _, entry := range entries {
		client, err := newRegistryClient(ctx, cfg, entry, loadAWS)
		if err != nil {
			return Registry{}, err
		}

		apps[entry.Name] = resolvedApp{
			identity: AppIdentity{
				Name:           entry.Name,
				ApplicationID:  entry.ApplicationID,
				InstallationID: entry.InstallationID,
			},
			client:    client,
			keySource: keySource(entry.PrivateKeyARN),
		}
	}

	registry := Registry{apps: apps}
	if err := registry.verify(ctx); err != nil {
		return Registry{}, err
	}

	registry.logEntries()

	return registry, nil
}

// Resolve maps an app name to the identity its tokens are minted through.
// A disabled app resolves to nothing: enabled state is not part of this
// answer, so a caller cannot act on a disabled app by neglecting to check it.
//
// This is the single enforcement point shared by profile compilation and the
// request path, which is what makes a compiled profile and a live request
// agree on which apps are usable.
func (r Registry) Resolve(name string) (AppIdentity, bool) {
	app, found := r.apps[name]
	if !found || !app.enabled {
		return AppIdentity{}, false
	}
	return app.identity, true
}

// IsUsable reports whether a profile may name this app. It is Resolve, so
// compilation and the request path cannot drift apart.
func (r Registry) IsUsable(name string) bool {
	_, usable := r.Resolve(name)
	return usable
}

// DefaultIdentity is the identity of the app configured by GITHUB_APP_*.
func (r Registry) DefaultIdentity() AppIdentity {
	return r.apps[DefaultAppName].identity
}

// CreateAccessToken mints an installation token through the named app.
//
// The identity is re-resolved rather than trusted: it may have travelled
// through a cache payload or a long-lived request value, and the registry is
// the only authority on which apps are usable.
func (r Registry) CreateAccessToken(ctx context.Context, app AppIdentity, repoNames []string, scopes []string) (string, time.Time, error) {
	resolved, found := r.apps[app.Name]
	if !found || !resolved.enabled {
		return "", time.Time{}, fmt.Errorf("cannot mint through app %q: %w", app.Name, ErrAppUnknown)
	}

	// A name is a label on an identity, and an operator may repoint it. A
	// request carrying the old identity must not mint through the new one.
	if resolved.identity != app {
		return "", time.Time{}, fmt.Errorf("app %q no longer refers to application %d installation %d: %w",
			app.Name, app.ApplicationID, app.InstallationID, ErrAppUnknown)
	}

	return resolved.client.CreateAccessToken(ctx, repoNames, scopes)
}

// verify establishes that every registry app is installed on the same account
// as the default app.
//
// The default app's account is the reference, so no new variable is required
// of an existing deployment. Queries are issued concurrently, so the phase
// costs roughly the slowest one rather than their sum. No time budget governs
// it: a budget's expiry would be evidence about this service rather than about
// any app, which is the wrong basis on which to disable one.
func (r Registry) verify(ctx context.Context) error {
	type result struct {
		name    string
		account installationAccount
		err     error
	}

	results := make(chan result, len(r.apps))

	var wg sync.WaitGroup
	for name, app := range r.apps {
		wg.Go(func() {
			account, err := app.client.InstallationAccount(ctx)
			results <- result{name: name, account: account, err: err}
		})
	}

	wg.Wait()
	close(results)

	accounts := make(map[string]installationAccount, len(r.apps))
	failures := make(map[string]error, len(r.apps))
	for res := range results {
		if res.err != nil {
			failures[res.name] = res.err
			continue
		}
		accounts[res.name] = res.account
	}

	// The default app is the exception to "disable, don't fail". If the
	// service cannot query its own installation it cannot authenticate to
	// GitHub as itself, so minting is broken regardless and a process that
	// continued would serve failures while appearing healthy.
	if err, failed := failures[DefaultAppName]; failed {
		return fmt.Errorf("default app installation could not be queried: %w", err)
	}

	reference := accounts[DefaultAppName]

	for name, app := range r.apps {
		if name == DefaultAppName {
			app.accountLogin = reference.Login
			r.apps[name] = app
			continue
		}

		if err, failed := failures[name]; failed {
			app.enabled = false
			app.disabledReason = fmt.Sprintf("installation could not be queried: %v", err)
			r.apps[name] = app
			continue
		}

		account := accounts[name]
		if account.ID != reference.ID {
			app.enabled = false
			app.disabledReason = fmt.Sprintf("installed on account %q, expected %q", account.Login, reference.Login)
			r.apps[name] = app
			continue
		}

		app.enabled = true
		app.accountLogin = account.Login
		r.apps[name] = app
	}

	return nil
}

// logEntries records the whole registry once at startup: it is the operator's
// only view of which apps a running instance considers usable, since disabled
// is terminal until restart.
func (r Registry) logEntries() {
	for _, app := range r.apps {
		slog.Info("github app registry entry", "app", app)
	}
}

// newRegistryClient builds the minting client for one registry entry.
//
// The entry inherits the default app's API URL: the registry is a set of
// credentials against one GitHub deployment, not a set of GitHub deployments.
func newRegistryClient(ctx context.Context, cfg appconfig.GithubConfig, entry appEntryConfig, loadAWS AWSConfigLoader) (Client, error) {
	entryCfg := appconfig.GithubConfig{
		APIURL:         cfg.APIURL,
		PrivateKey:     entry.PrivateKey,
		PrivateKeyARN:  entry.PrivateKeyARN,
		ApplicationID:  entry.ApplicationID,
		InstallationID: entry.InstallationID,
	}

	// Validate the key before building the client so an unparseable key is
	// reported as such, rather than as a transport construction failure with
	// the parser's message attached.
	if entry.PrivateKey != "" {
		if _, err := parsePrivateKeyPEM(entry.PrivateKey); err != nil {
			return Client{}, fmt.Errorf("app %q: %w", entry.Name, ErrPrivateKeyInvalid)
		}
	}

	client, err := New(ctx, entryCfg, WithAppTransport, WithAWSConfigLoader(loadAWS))
	if err != nil {
		// The wrapped error describes client construction, not key content:
		// the key has already been parsed successfully above, and the KMS path
		// contacts nothing here.
		return Client{}, fmt.Errorf("app %q: could not construct GitHub client: %w", entry.Name, err)
	}

	return client, nil
}

// parseAppEntries decodes and validates GITHUB_APPS.
//
// Every failure here is deploy-blocking rather than degrading: configuration
// with no single unambiguous meaning fails identically on every instance,
// where a partial interpretation would differ between them. Each message
// identifies the offending entry by name, or by index when the name itself is
// the problem, and never reproduces any part of a key or ARN.
func parseAppEntries(raw string) ([]appEntryConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	decoder := json.NewDecoder(strings.NewReader(raw))

	// An unrecognised field is rejected for the same reason the profile YAML
	// rejects one: a typo that is silently ignored is a credential configured
	// differently from how it reads.
	decoder.DisallowUnknownFields()

	var entries []appEntryConfig
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("GITHUB_APPS is not valid: %w", err)
	}

	seen := make(map[string]struct{}, len(entries))
	for index, entry := range entries {
		if err := validateAppEntry(index, entry); err != nil {
			return nil, err
		}

		if _, duplicate := seen[entry.Name]; duplicate {
			return nil, fmt.Errorf("GITHUB_APPS entry %d: duplicate app name %q", index, entry.Name)
		}
		seen[entry.Name] = struct{}{}
	}

	return entries, nil
}

func validateAppEntry(index int, entry appEntryConfig) error {
	if entry.Name == DefaultAppName {
		return fmt.Errorf("GITHUB_APPS entry %d: name %q is reserved for the app configured by GITHUB_APP_ID", index, DefaultAppName)
	}

	if len(entry.Name) > maxAppNameLength {
		return fmt.Errorf("GITHUB_APPS entry %d: name exceeds %d characters", index, maxAppNameLength)
	}

	if !appNamePattern.MatchString(entry.Name) {
		return fmt.Errorf("GITHUB_APPS entry %d: name %q must match %s", index, entry.Name, appNamePattern)
	}

	if entry.ApplicationID <= 0 {
		return fmt.Errorf("GITHUB_APPS entry %q: appId must be a positive integer", entry.Name)
	}

	if entry.InstallationID <= 0 {
		return fmt.Errorf("GITHUB_APPS entry %q: installationId must be a positive integer", entry.Name)
	}

	hasKey := entry.PrivateKey != ""
	hasARN := entry.PrivateKeyARN != ""

	if hasKey && hasARN {
		return fmt.Errorf("GITHUB_APPS entry %q: declares both privateKey and privateKeyArn, expected exactly one", entry.Name)
	}
	if !hasKey && !hasARN {
		return fmt.Errorf("GITHUB_APPS entry %q: declares neither privateKey nor privateKeyArn, expected exactly one", entry.Name)
	}

	return nil
}
