package main

import (
	"encoding/json/v2"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vendedToken's identifiers must stay non-zero, or a withholding assertion
// passes against a marshaller that discloses.
var vendedToken = vendor.ProfileToken{
	OrganizationSlug:    "acme",
	Profile:             "org:publish",
	VendedRepositoryURL: "https://github.com/acme/widget",
	Repositories:        profile.NewSpecificScope("widget"),
	Permissions:         []string{"contents:read"},
	App:                 "publisher",
	ApplicationID:       4242,
	InstallationID:      8484,
	Token:               "minted-token",
	HashedToken:         "hashed-token",
	Expiry:              time.Date(2024, time.May, 7, 17, 59, 36, 0, time.UTC),
}

func marshalToMap(t *testing.T, m TokenResponseMarshaler, token vendor.ProfileToken) map[string]any {
	t.Helper()

	data, err := m.MarshalToken(token)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

// Asserted as a difference between the two shapes rather than a key list, so
// one assertion catches both a leak and an accidentally dropped field.
func TestMarshalToken_WithholdingDropsExactlyTheIdentifiers(t *testing.T) {
	disclosed := marshalToMap(t, newTokenResponseMarshaler(true), vendedToken)
	withheld := marshalToMap(t, newTokenResponseMarshaler(false), vendedToken)

	dropped := slices.Sorted(maps.Keys(disclosed))
	dropped = slices.DeleteFunc(dropped, func(k string) bool {
		_, kept := withheld[k]
		return kept
	})

	assert.Equal(t, []string{"appId", "installationId"}, dropped)
	for k, v := range withheld {
		assert.Equal(t, disclosed[k], v, "key %q must be unchanged by withholding", k)
	}
}

// The zero-value case is deliberate: a marshaller nobody constructed must
// withhold.
func TestMarshalToken_IdentifierKeys(t *testing.T) {
	stale := vendedToken
	stale.ApplicationID, stale.InstallationID = 0, 0

	tests := []struct {
		name      string
		marshaler TokenResponseMarshaler
		token     vendor.ProfileToken
		expected  map[string]any
		absent    []string
	}{
		{
			name:      "disclosing carries both identifiers",
			marshaler: disclosed,
			token:     vendedToken,
			expected:  map[string]any{"app": "publisher", "appId": float64(4242), "installationId": float64(8484)},
		},
		{
			name:      "withholding carries neither",
			marshaler: withheld,
			token:     vendedToken,
			expected:  map[string]any{"app": "publisher"},
			absent:    []string{"appId", "installationId"},
		},
		{
			name:      "the zero value withholds",
			marshaler: TokenResponseMarshaler{},
			token:     vendedToken,
			expected:  map[string]any{"app": "publisher"},
			absent:    []string{"appId", "installationId"},
		},
		{
			name:      "disclosing a stale cached token",
			marshaler: disclosed,
			token:     stale,
			expected:  map[string]any{"app": "publisher"},
			absent:    []string{"appId", "installationId"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := marshalToMap(t, tt.marshaler, tt.token)

			for key, want := range tt.expected {
				assert.Equal(t, want, response[key])
			}
			for _, key := range tt.absent {
				assert.NotContains(t, response, key)
			}
		})
	}
}

func credentialKeys(t *testing.T, m TokenResponseMarshaler, token vendor.ProfileToken) ([]string, map[string]string) {
	t.Helper()

	u, err := token.URL()
	require.NoError(t, err)

	props := m.CredentialProperties(token, u)

	keys := make([]string, 0, props.Len())
	values := make(map[string]string, props.Len())
	for i := props.Iter(); i.HasNext(); {
		k, v := i.Next()
		keys = append(keys, k)
		values[k] = v
	}
	return keys, values
}

// gitCredentialKeys are the properties git has always received, in order:
// a credential helper's output is a protocol, not a map.
var gitCredentialKeys = []string{"protocol", "host", "path", "username", "password", "password_expiry_utc"}

// All three chinmina_ keys are new to git-credentials clients — unlike the JSON
// response, which has always carried the app name — so all three are gated.
func TestCredentialProperties_Keys(t *testing.T) {
	stale := vendedToken
	stale.ApplicationID, stale.InstallationID = 0, 0

	tests := []struct {
		name      string
		marshaler TokenResponseMarshaler
		token     vendor.ProfileToken
		expected  []string
		values    map[string]string
	}{
		{
			name:      "withholding emits only git's keys",
			marshaler: withheld,
			token:     vendedToken,
			expected:  gitCredentialKeys,
			values:    map[string]string{"username": "x-access-token", "password": "minted-token"},
		},
		{
			name:      "the zero value withholds",
			marshaler: TokenResponseMarshaler{},
			token:     vendedToken,
			expected:  gitCredentialKeys,
		},
		{
			name:      "disclosing appends the chinmina keys",
			marshaler: disclosed,
			token:     vendedToken,
			expected:  append(slices.Clone(gitCredentialKeys), "chinmina_app_name", "chinmina_app_id", "chinmina_installation_id"),
			values: map[string]string{
				"chinmina_app_name":        "publisher",
				"chinmina_app_id":          "4242",
				"chinmina_installation_id": "8484",
			},
		},
		{
			name:      "disclosing a stale cached token names its app and nothing more",
			marshaler: disclosed,
			token:     stale,
			expected:  append(slices.Clone(gitCredentialKeys), "chinmina_app_name"),
			values:    map[string]string{"chinmina_app_name": "publisher"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, values := credentialKeys(t, tt.marshaler, tt.token)

			assert.Equal(t, tt.expected, keys)
			for key, want := range tt.values {
				assert.Equal(t, want, values[key])
			}
		})
	}
}

// WriteProperties rejects a key containing '\n', '=' or NUL, so the new keys
// have to be shown to survive it.
func TestCredentialProperties_KeysAreWritableByTheHelperProtocol(t *testing.T) {
	u, err := vendedToken.URL()
	require.NoError(t, err)

	var out strings.Builder
	require.NoError(t, credentialhandler.WriteProperties(
		newTokenResponseMarshaler(true).CredentialProperties(vendedToken, u), &out))

	assert.Contains(t, out.String(), "chinmina_installation_id=8484\n")
}

// null and {} are the existing wire shapes; choosing the response shape at the
// call site must not disturb them.
func TestMarshalToken_NilSlicesStayNull(t *testing.T) {
	unscoped := vendedToken
	unscoped.Permissions = nil
	unscoped.Repositories = profile.RepositoryScope{}

	for _, m := range []TokenResponseMarshaler{withheld, disclosed, {}} {
		data, err := m.MarshalToken(unscoped)
		require.NoError(t, err)

		assert.Contains(t, string(data), `"permissions":null`)
		assert.Contains(t, string(data), `"repositories":{}`)
	}
}
