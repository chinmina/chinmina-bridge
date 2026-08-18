package github_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The registry's contract is: which names are usable, which installation each
// mints through, and what reaches the log. Enabled state is deliberately not
// readable except through a name failing to resolve, so these tests assert
// resolution rather than internal flags.

const (
	defaultAppID          = int64(111)
	defaultInstallationID = int64(222)

	// accountSameOrg is the default app's installation account. Apps are
	// compared on account ID, never login, so tests distinguish organizations
	// by ID alone.
	accountSameOrg  = int64(9001)
	accountOtherOrg = int64(9002)
)

// registryFixture is one GitHub mock plus the default app configuration
// pointed at it. Registry entries inherit the API URL, so everything a test
// configures resolves against the same mock.
type registryFixture struct {
	mock *testhelpers.MockGitHubServer
	cfg  config.GithubConfig
}

func newRegistryFixture(t *testing.T, appsJSON string) registryFixture {
	t.Helper()
	testhelpers.SetupLogger(t)

	mock := testhelpers.SetupMockGitHubServer(t)
	t.Cleanup(mock.Close)

	mock.DefaultInstallation = testhelpers.MockInstallation{
		AccountID:    accountSameOrg,
		AccountLogin: "acme",
	}

	return registryFixture{
		mock: mock,
		cfg: config.GithubConfig{
			APIURL:         mock.Server.URL,
			PrivateKey:     generateKey(t),
			ApplicationID:  defaultAppID,
			InstallationID: defaultInstallationID,
			Apps:           appsJSON,
		},
	}
}

// build constructs the registry the way production does: a default client
// first, then the registry reusing it.
func (f registryFixture) build(t *testing.T) (github.Registry, error) {
	t.Helper()

	return f.buildWithContext(t, t.Context())
}

func (f registryFixture) buildWithContext(t *testing.T, ctx context.Context) (github.Registry, error) {
	t.Helper()

	defaultClient, err := github.New(ctx, f.cfg)
	require.NoError(t, err)

	return github.NewRegistry(ctx, f.cfg, defaultClient)
}

// appsJSON renders a GITHUB_APPS array from entries expressed as maps, so a
// test can express a malformed entry (unknown field, missing key, wrong type)
// as directly as a well-formed one.
func appsJSON(t *testing.T, entries ...map[string]any) string {
	t.Helper()

	encoded, err := json.Marshal(entries)
	require.NoError(t, err)

	return string(encoded)
}

func validEntry(t *testing.T, name string, appID, installationID int64) map[string]any {
	t.Helper()

	return map[string]any{
		"name":           name,
		"appId":          appID,
		"installationId": installationID,
		"privateKey":     generateKey(t),
	}
}

// --- Configuration validation (R5–R11, R15) ---

// Every case here is deploy-blocking: configuration with no single
// unambiguous meaning must fail identically on every instance rather than
// being partially interpreted.
func TestRegistry_MalformedConfigurationPreventsStartup(t *testing.T) {
	validKey := generateKey(t)

	tests := []struct {
		name        string
		apps        string
		errContains string
	}{
		{
			name:        "not JSON",
			apps:        `{not json`,
			errContains: "GITHUB_APPS is not valid",
		},
		{
			name:        "not a JSON array",
			apps:        `{"name":"packages"}`,
			errContains: "GITHUB_APPS is not valid",
		},
		{
			name:        "unrecognised field",
			apps:        `[{"name":"packages","appId":1,"installationId":2,"privateKeyArn":"arn:aws:kms:x","organization":"acme"}]`,
			errContains: "GITHUB_APPS is not valid",
		},
		{
			name:        "duplicate name",
			apps:        fmt.Sprintf(`[{"name":"packages","appId":1,"installationId":2,"privateKey":%q},{"name":"packages","appId":3,"installationId":4,"privateKey":%q}]`, validKey, validKey),
			errContains: `duplicate app name "packages"`,
		},
		{
			name:        "name is default",
			apps:        `[{"name":"default","appId":1,"installationId":2,"privateKeyArn":"arn:aws:kms:x"}]`,
			errContains: "is reserved",
		},
		{
			name:        "name has uppercase",
			apps:        `[{"name":"Packages","appId":1,"installationId":2,"privateKeyArn":"arn:aws:kms:x"}]`,
			errContains: "must match",
		},
		{
			name:        "name has a leading separator",
			apps:        `[{"name":"-packages","appId":1,"installationId":2,"privateKeyArn":"arn:aws:kms:x"}]`,
			errContains: "must match",
		},
		{
			name:        "name is empty",
			apps:        `[{"name":"","appId":1,"installationId":2,"privateKeyArn":"arn:aws:kms:x"}]`,
			errContains: "must match",
		},
		{
			name:        "name exceeds 64 characters",
			apps:        fmt.Sprintf(`[{"name":%q,"appId":1,"installationId":2,"privateKeyArn":"arn:aws:kms:x"}]`, strings.Repeat("a", 65)),
			errContains: "exceeds 64 characters",
		},
		{
			name:        "application ID is zero",
			apps:        `[{"name":"packages","appId":0,"installationId":2,"privateKeyArn":"arn:aws:kms:x"}]`,
			errContains: "appId must be a positive integer",
		},
		{
			name:        "application ID is negative",
			apps:        `[{"name":"packages","appId":-1,"installationId":2,"privateKeyArn":"arn:aws:kms:x"}]`,
			errContains: "appId must be a positive integer",
		},
		{
			name:        "installation ID is zero",
			apps:        `[{"name":"packages","appId":1,"installationId":0,"privateKeyArn":"arn:aws:kms:x"}]`,
			errContains: "installationId must be a positive integer",
		},
		{
			name:        "both key sources",
			apps:        fmt.Sprintf(`[{"name":"packages","appId":1,"installationId":2,"privateKey":%q,"privateKeyArn":"arn:aws:kms:x"}]`, validKey),
			errContains: "declares both privateKey and privateKeyArn",
		},
		{
			name:        "neither key source",
			apps:        `[{"name":"packages","appId":1,"installationId":2}]`,
			errContains: "declares neither privateKey nor privateKeyArn",
		},
		{
			name:        "unparseable private key",
			apps:        `[{"name":"packages","appId":1,"installationId":2,"privateKey":"-----BEGIN RSA PRIVATE KEY-----\nnope\n-----END RSA PRIVATE KEY-----"}]`,
			errContains: "private key could not be parsed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRegistryFixture(t, tt.apps)

			_, err := fixture.build(t)

			require.Error(t, err)
			assert.ErrorContains(t, err, tt.errContains)
		})
	}
}

// A configuration error must never reproduce the credential it failed on: the
// operator already has the key, and a log aggregator should not.
func TestRegistry_ConfigurationErrorsOmitKeyMaterial(t *testing.T) {
	const arn = "arn:aws:kms:ap-southeast-2:123456789012:key/super-secret-key-id"
	badKey := "-----BEGIN RSA PRIVATE KEY-----\nQUJDREVGRw==\n-----END RSA PRIVATE KEY-----"

	tests := []struct {
		name   string
		apps   string
		secret string
	}{
		{
			name:   "unparseable key is not echoed",
			apps:   fmt.Sprintf(`[{"name":"packages","appId":1,"installationId":2,"privateKey":%q}]`, badKey),
			secret: "QUJDREVGRw==",
		},
		{
			name:   "ARN is not echoed",
			apps:   fmt.Sprintf(`[{"name":"packages","appId":0,"installationId":2,"privateKeyArn":%q}]`, arn),
			secret: arn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRegistryFixture(t, tt.apps)

			_, err := fixture.build(t)

			require.Error(t, err)
			assert.NotContains(t, err.Error(), tt.secret)
			// The entry is still identifiable: an error naming nothing is not
			// actionable.
			assert.Contains(t, err.Error(), "packages")
		})
	}
}

// --- Verification outcomes (R12–R19) ---

func TestRegistry_EnablesAppsOnTheDefaultAppsAccount(t *testing.T) {
	fixture := newRegistryFixture(t, appsJSON(t,
		validEntry(t, "packages", 333, 444),
		validEntry(t, "deploy", 555, 666),
	))

	registry, err := fixture.build(t)
	require.NoError(t, err)

	packages, usable := registry.Resolve("packages")
	assert.True(t, usable)
	assert.Equal(t, github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 444}, packages)

	deploy, usable := registry.Resolve("deploy")
	assert.True(t, usable)
	assert.Equal(t, github.AppIdentity{Name: "deploy", ApplicationID: 555, InstallationID: 666}, deploy)

	assert.Equal(t, github.AppIdentity{Name: "default", ApplicationID: defaultAppID, InstallationID: defaultInstallationID},
		registry.DefaultIdentity())
}

// A registry app on another account is disabled rather than fatal: one
// misconfigured credential must not take down vending for every other profile.
// Disabled is indistinguishable from absent, so no caller can act on it by
// forgetting to check a flag.
func TestRegistry_DisablesAppOnADifferentAccount(t *testing.T) {
	fixture := newRegistryFixture(t, appsJSON(t,
		validEntry(t, "packages", 333, 444),
		validEntry(t, "deploy", 555, 666),
	))
	fixture.mock.SetInstallation(444, testhelpers.MockInstallation{
		AccountID:    accountOtherOrg,
		AccountLogin: "someone-else",
	})

	registry, err := fixture.build(t)
	require.NoError(t, err)

	assert.False(t, registry.IsUsable("packages"))
	assert.True(t, registry.IsUsable("deploy"), "an unrelated app must be unaffected")
	assert.True(t, registry.IsUsable("default"))
}

func TestRegistry_DisablesAppWhoseInstallationCannotBeQueried(t *testing.T) {
	fixture := newRegistryFixture(t, appsJSON(t,
		validEntry(t, "packages", 333, 444),
		validEntry(t, "deploy", 555, 666),
	))
	fixture.mock.SetInstallation(444, testhelpers.MockInstallation{StatusCode: 500})

	registry, err := fixture.build(t)
	require.NoError(t, err, "one unreachable app must not prevent startup")

	assert.False(t, registry.IsUsable("packages"))
	assert.True(t, registry.IsUsable("deploy"))
}

// The default app is the exception. If the service cannot query its own
// installation it cannot authenticate as itself, so minting is broken
// regardless and a process that continued would serve failures while
// appearing healthy.
func TestRegistry_FailsWhenTheDefaultAppsInstallationCannotBeQueried(t *testing.T) {
	fixture := newRegistryFixture(t, appsJSON(t, validEntry(t, "packages", 333, 444)))
	fixture.mock.SetInstallation(defaultInstallationID, testhelpers.MockInstallation{StatusCode: 401})

	_, err := fixture.build(t)

	assert.ErrorContains(t, err, "default app installation could not be queried")
}

// R19: a deployment not using the feature pays nothing for its existence.
func TestRegistry_QueriesNoInstallationWithoutAConfiguredRegistry(t *testing.T) {
	fixture := newRegistryFixture(t, "")

	registry, err := fixture.build(t)
	require.NoError(t, err)

	assert.Equal(t, 0, fixture.mock.InstallationQueryCount())
	assert.True(t, registry.IsUsable("default"))
	assert.False(t, registry.IsUsable("packages"))
}

// --- Minting (R2, R33) ---

func TestRegistry_MintsThroughTheResolvedAppsInstallation(t *testing.T) {
	fixture := newRegistryFixture(t, appsJSON(t, validEntry(t, "packages", 333, 444)))
	fixture.mock.SetInstallation(444, testhelpers.MockInstallation{
		AccountID:    accountSameOrg,
		AccountLogin: "acme",
		Token:        "packages-token",
	})

	registry, err := fixture.build(t)
	require.NoError(t, err)

	packages, usable := registry.Resolve("packages")
	require.True(t, usable)

	token, _, err := registry.CreateAccessToken(t.Context(), packages, []string{"widget"}, []string{"contents:read"})
	require.NoError(t, err)

	assert.Equal(t, "packages-token", token)
	assert.Equal(t, 1, fixture.mock.TokenRequestCount())
}

// An identity may arrive from a long-lived request value, so the registry
// re-resolves rather than trusting it. An unknown or repointed name must not
// mint.
func TestRegistry_RefusesToMintThroughAnUnresolvableIdentity(t *testing.T) {
	fixture := newRegistryFixture(t, appsJSON(t, validEntry(t, "packages", 333, 444)))
	fixture.mock.SetInstallation(444, testhelpers.MockInstallation{StatusCode: 500})

	registry, err := fixture.build(t)
	require.NoError(t, err)

	tests := []struct {
		name     string
		identity github.AppIdentity
	}{
		{
			name:     "disabled app",
			identity: github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 444},
		},
		{
			name:     "unknown app",
			identity: github.AppIdentity{Name: "nonexistent", ApplicationID: 1, InstallationID: 2},
		},
		{
			name:     "name repointed to another installation",
			identity: github.AppIdentity{Name: "default", ApplicationID: defaultAppID, InstallationID: 999},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := registry.CreateAccessToken(t.Context(), tt.identity, nil, []string{"contents:read"})

			assert.ErrorIs(t, err, github.ErrAppUnknown)
		})
	}
}

// --- Startup logging (R48, R49) ---

func TestRegistry_LogsEveryEntryWithoutKeyMaterial(t *testing.T) {
	const arn = "arn:aws:kms:ap-southeast-2:123456789012:key/super-secret-key-id"
	privateKey := generateKey(t)

	// A purposely unbound endpoint: KMS key construction contacts nothing, so
	// this must not be reached during startup.
	t.Setenv("AWS_ENDPOINT_URL", "http://localhost:20987/not-bound")

	fixture := newRegistryFixture(t, appsJSON(t,
		validEntry(t, "packages", 333, 444),
		map[string]any{
			"name":           "deploy",
			"appId":          555,
			"installationId": 666,
			"privateKeyArn":  arn,
		},
	))
	fixture.cfg.PrivateKey = privateKey

	logged := captureLog(t)

	_, err := fixture.build(t)
	require.NoError(t, err)

	output := logged.String()

	// R48: every configured app is identifiable, with its verified
	// organization and enabled state.
	for _, expected := range []string{
		"name=packages", "applicationID=333", "installationID=444",
		"name=deploy", "applicationID=555", "installationID=666",
		"name=default", "organization=acme", "enabled=true",
	} {
		assert.Contains(t, output, expected)
	}

	// R49: nothing else. The ARN is withheld along with the key — it names the
	// credential and its account, which a log has no use for.
	assert.NotContains(t, output, arn)
	assert.NotContains(t, output, "super-secret-key-id")
	assert.NotContains(t, output, privateKey)
	assert.NotContains(t, output, "PRIVATE KEY")
	assert.Contains(t, output, "keySource=privateKeyArn")
	assert.Contains(t, output, "keySource=privateKey")
}

func TestRegistry_LogsWhyAnAppIsDisabled(t *testing.T) {
	fixture := newRegistryFixture(t, appsJSON(t, validEntry(t, "packages", 333, 444)))
	fixture.mock.SetInstallation(444, testhelpers.MockInstallation{
		AccountID:    accountOtherOrg,
		AccountLogin: "someone-else",
	})

	logged := captureLog(t)

	_, err := fixture.build(t)
	require.NoError(t, err)

	output := logged.String()
	assert.Contains(t, output, "enabled=false")
	assert.Contains(t, output, "someone-else")
}

// captureLog redirects the default logger into a buffer for the duration of
// the test, so assertions can be made about what an operator would see.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	buffer := &bytes.Buffer{}
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })

	slog.SetDefault(slog.New(slog.NewTextHandler(buffer, &slog.HandlerOptions{Level: slog.LevelDebug})))

	return buffer
}
