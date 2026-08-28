package github

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	appconfig "github.com/chinmina/chinmina-bridge/internal/config"
)

// DefaultAppName names the app configured by the GITHUB_APP_* variables. A
// profile may name it explicitly; omitting the app property resolves the same.
const DefaultAppName = "default"

// maxAppNameLength bounds a registry entry's name: names become metric
// attributes, so unbounded length is unbounded cardinality.
const maxAppNameLength = 64

var appNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// ErrPrivateKeyInvalid deliberately breaks the %w convention: the parser's
// message may quote the key.
var ErrPrivateKeyInvalid = errors.New("private key could not be parsed")

// ErrAppUnknown does not distinguish a disabled app from an absent one:
// enabled state is for logging only.
var ErrAppUnknown = errors.New("no such app")

// AppIdentity is plain data rather than a client, so it can travel on a request
// value or into a cache key.
type AppIdentity struct {
	Name           string
	ApplicationID  int64
	InstallationID int64
}

func (i AppIdentity) IsZero() bool {
	return i == AppIdentity{}
}

// privateKeyPEM redacts under every fmt verb, so no format string can print a
// key: LogValue guards slog, this guards fmt.
type privateKeyPEM string

func (privateKeyPEM) String() string { return "[redacted]" }

func (privateKeyPEM) GoString() string { return `"[redacted]"` }

func (privateKeyPEM) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[redacted]")
}

type appEntryConfig struct {
	Name           string        `json:"name"`
	ApplicationID  int64         `json:"appId"`
	InstallationID int64         `json:"installationId"`
	PrivateKey     privateKeyPEM `json:"privateKey"`
	PrivateKeyARN  string        `json:"privateKeyArn"`
}

// keySource names where a key comes from without disclosing it.
func keySource(privateKeyARN string) string {
	if privateKeyARN != "" {
		return "privateKeyArn"
	}
	return "privateKey"
}

// LogValue withholds the key and its ARN: this record identifies an entry, not
// its credential. Diagnostics may carry an ARN; disabledReason does.
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

	// Disabled is terminal until restart: re-verification would make the enabled
	// set depend on when a timer fired.
	enabled bool

	// Empty when verification failed.
	accountLogin string

	// Carries upstream error text, so it may name a credential. Startup log only.
	disabledReason string
}

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

// Registry is written only by its constructor, so the request path needs no
// lock. DefaultAppName is always present.
type Registry struct {
	apps map[string]resolvedApp
}

// NewRegistry requires the long-lived server context: ctx reaches KMS signing
// key construction, and a startup-scoped one boots cleanly then fails every mint.
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

	// Deliberate: deployments not using the feature query no installation at all.
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

// Resolve yields nothing for a disabled app, so no caller can act on one by
// neglecting to check a flag.
func (r Registry) Resolve(name string) (AppIdentity, bool) {
	app, found := r.apps[name]
	if !found || !app.enabled {
		return AppIdentity{}, false
	}
	return app.identity, true
}

// IsUsable is Resolve, so compilation and the request path cannot drift apart.
func (r Registry) IsUsable(name string) bool {
	_, usable := r.Resolve(name)
	return usable
}

func (r Registry) DefaultIdentity() AppIdentity {
	return r.apps[DefaultAppName].identity
}

// CreateAccessToken re-resolves the identity rather than trusting it: it may
// have come from a cache payload, and only the registry knows what is usable.
func (r Registry) CreateAccessToken(ctx context.Context, app AppIdentity, repoNames []string, scopes []string) (string, time.Time, error) {
	resolved, found := r.apps[app.Name]
	if !found || !resolved.enabled {
		return "", time.Time{}, fmt.Errorf("cannot mint through app %q: %w", app.Name, ErrAppUnknown)
	}

	// An operator may repoint a name; the old identity must not mint through it.
	if resolved.identity != app {
		return "", time.Time{}, fmt.Errorf("app %q no longer refers to application %d installation %d: %w",
			app.Name, app.ApplicationID, app.InstallationID, ErrAppUnknown)
	}

	return resolved.client.CreateAccessToken(ctx, repoNames, scopes)
}

// verify runs under no time budget: an expiring budget would be evidence about
// this service, not about an app.
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

	// The exception to "disable, don't fail": a service that cannot authenticate
	// as itself would serve failures while appearing healthy.
	if err := queried[DefaultAppName].err; err != nil {
		return fmt.Errorf("default app installation could not be queried: %w", err)
	}

	// The reference compares equal to itself, so the default app needs no case.
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

// logEntries is the operator's only view of which apps an instance considers
// usable.
func (r Registry) logEntries() {
	for _, app := range r.apps {
		slog.Info("github app registry entry", "app", app)
	}
}

// newRegistryClient gives every entry the default app's API URL: one GitHub
// deployment, many credentials.
func newRegistryClient(ctx context.Context, cfg appconfig.GithubConfig, entry appEntryConfig, loadAWS AWSConfigLoader) (Client, error) {
	entryCfg := appconfig.GithubConfig{
		APIURL:         cfg.APIURL,
		PrivateKey:     string(entry.PrivateKey),
		PrivateKeyARN:  entry.PrivateKeyARN,
		ApplicationID:  entry.ApplicationID,
		InstallationID: entry.InstallationID,
	}

	// Parse first, so an unparseable key is reported as such rather than as a
	// transport construction failure.
	if entry.PrivateKey != "" {
		if _, err := parsePrivateKeyPEM(string(entry.PrivateKey)); err != nil {
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

// parseAppEntries treats every failure as deploy-blocking: ambiguous
// configuration must fail identically on every instance.
func parseAppEntries(raw string) ([]appEntryConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	// Unmarshal rather than a streaming decoder: json/v2 requires exactly one JSON
	// value, so a concatenated variable cannot pass with the remainder discarded.
	var entries []appEntryConfig
	if err := json.Unmarshal([]byte(raw), &entries, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("GITHUB_APPS is not valid: %w", err)
	}

	// null unmarshals to a nil slice without error, and an empty registry skips
	// verification: a deployment that configured apps must not start without them.
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
