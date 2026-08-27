package github

import (
	"context"
	"encoding/json/v2"
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

// maxAppNameLength bounds a registry entry's name: names become metric
// attributes, so unbounded length is unbounded cardinality.
const maxAppNameLength = 64

// appNamePattern constrains a registry entry's name to a lower-case, URL- and
// label-safe form.
var appNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// ErrPrivateKeyInvalid reports an unparseable private key. A deliberate
// exception to the %w convention: the parser's message may quote the key.
var ErrPrivateKeyInvalid = errors.New("private key could not be parsed")

// ErrAppUnknown reports a name that resolves to no usable app. Disabled apps
// are indistinguishable from absent ones: enabled state is for logging only.
var ErrAppUnknown = errors.New("no such app")

// AppIdentity is what a profile's app name resolves to. It is plain data, not a
// client, so it can travel on a request value or into a cache key.
type AppIdentity struct {
	Name           string
	ApplicationID  int64
	InstallationID int64
}

// IsZero reports whether the identity was never resolved.
func (i AppIdentity) IsZero() bool {
	return i == AppIdentity{}
}

// appEntryConfig is one GITHUB_APPS entry as configured.
type appEntryConfig struct {
	Name           string `json:"name"`
	ApplicationID  int64  `json:"appId"`
	InstallationID int64  `json:"installationId"`
	PrivateKey     string `json:"privateKey"`
	PrivateKeyARN  string `json:"privateKeyArn"`
}

// keySource names where a key comes from without disclosing it.
func keySource(privateKeyARN string) string {
	if privateKeyARN != "" {
		return "privateKeyArn"
	}
	return "privateKey"
}

// LogValue omits both the private key and its ARN: the ARN names the
// credential and its account, and neither belongs in a log. Nothing logs an
// entry today; this exists so that the first thing to do so cannot print a
// private key by default.
func (e appEntryConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", e.Name),
		slog.Int64("applicationID", e.ApplicationID),
		slog.Int64("installationID", e.InstallationID),
		slog.String("keySource", keySource(e.PrivateKeyARN)),
	)
}

// resolvedApp is a registry entry after verification.
type resolvedApp struct {
	identity  AppIdentity
	client    Client
	keySource string

	// enabled is false for an app on another account, or one whose installation
	// could not be queried. Disabled is terminal until restart: re-verification
	// would make the enabled set depend on when a timer fired.
	enabled bool

	// accountLogin is the verified organization. Empty when verification failed.
	accountLogin string

	// disabledReason explains a false enabled, for the startup log only.
	disabledReason string
}

// LogValue is the startup record for one registry entry.
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
// through. It is written only by the constructor and never afterwards, so the
// request path needs no lock. The default app is always present under
// DefaultAppName.
type Registry struct {
	apps map[string]resolvedApp
}

// NewRegistry builds the app registry from the default app's configuration and
// the GITHUB_APPS entries alongside it.
//
// ctx must be the long-lived server context: it reaches KMS-backed signing key
// construction, and a key built under a startup-scoped context would boot
// cleanly and then fail every mint.
//
// Errors here are deploy-blocking: ambiguous configuration, or a default app
// that cannot authenticate as itself. A registry app that cannot be verified is
// disabled instead, so one unreachable credential does not stop the rest.
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

	// With no registry configured, startup queries no installation at all:
	// deployments not using the feature pay nothing for it.
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

// Resolve maps an app name to the identity its tokens are minted through. A
// disabled app resolves to nothing.
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

// CreateAccessToken mints an installation token through the named app. The
// identity is re-resolved rather than trusted: it may have arrived from a cache
// payload, and the registry is the only authority on which apps are usable.
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
// as the default app. Queries run concurrently and under no time budget: an
// expiring budget would be evidence about this service, not about an app.
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

	queried := make(map[string]result, len(r.apps))
	for res := range results {
		queried[res.name] = res
	}

	// The default app is the exception to "disable, don't fail": a service that
	// cannot authenticate as itself would serve failures while appearing
	// healthy.
	if err := queried[DefaultAppName].err; err != nil {
		return fmt.Errorf("default app installation could not be queried: %w", err)
	}

	// The default app is the reference, so it passes the comparison below
	// against itself: it needs no case of its own.
	reference := queried[DefaultAppName].account

	for name, app := range r.apps {
		res := queried[name]

		switch {
		case res.err != nil:
			app.enabled = false
			app.disabledReason = fmt.Sprintf("installation could not be queried: %v", res.err)
		case res.account.ID != reference.ID:
			app.enabled = false
			app.disabledReason = fmt.Sprintf("installed on account %q, expected %q", res.account.Login, reference.Login)
		default:
			app.enabled = true
			app.accountLogin = res.account.Login
		}

		r.apps[name] = app
	}

	return nil
}

// logEntries records the whole registry once at startup: the operator's only
// view of which apps an instance considers usable.
func (r Registry) logEntries() {
	for _, app := range r.apps {
		slog.Info("github app registry entry", "app", app)
	}
}

// newRegistryClient builds the minting client for one registry entry. Entries
// inherit the default app's API URL: one GitHub deployment, many credentials.
func newRegistryClient(ctx context.Context, cfg appconfig.GithubConfig, entry appEntryConfig, loadAWS AWSConfigLoader) (Client, error) {
	entryCfg := appconfig.GithubConfig{
		APIURL:         cfg.APIURL,
		PrivateKey:     entry.PrivateKey,
		PrivateKeyARN:  entry.PrivateKeyARN,
		ApplicationID:  entry.ApplicationID,
		InstallationID: entry.InstallationID,
	}

	// Validate the key before building the client so an unparseable key is
	// reported as such, not as a transport construction failure.
	if entry.PrivateKey != "" {
		if _, err := parsePrivateKeyPEM(entry.PrivateKey); err != nil {
			return Client{}, fmt.Errorf("app %q: %w", entry.Name, ErrPrivateKeyInvalid)
		}
	}

	client, err := New(ctx, entryCfg, WithAppTransport, WithAWSConfigLoader(loadAWS))
	if err != nil {
		// Safe to wrap: the key has already parsed, so this cannot quote it.
		return Client{}, fmt.Errorf("app %q: could not construct GitHub client: %w", entry.Name, err)
	}

	return client, nil
}

// parseAppEntries decodes and validates GITHUB_APPS. Failures are
// deploy-blocking: ambiguous configuration must fail identically everywhere.
func parseAppEntries(raw string) ([]appEntryConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	// json/v2's Unmarshal requires the input to be exactly one JSON value: a
	// streaming decoder stops at the end of the first value, so a truncated or
	// concatenated variable would be silently accepted with the remainder
	// discarded.
	//
	// RejectUnknownMembers: a silently ignored typo is a credential configured
	// differently from how it reads.
	var entries []appEntryConfig
	if err := json.Unmarshal([]byte(raw), &entries, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("GITHUB_APPS is not valid: %w", err)
	}

	// JSON null unmarshals to a nil slice without error, and an empty registry
	// skips installation verification entirely. A deployment that believes it
	// configured apps must not start with only the default app.
	if entries == nil {
		return nil, errors.New("GITHUB_APPS is not valid: expected a JSON array, found null")
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
