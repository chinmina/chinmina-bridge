package github

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A configured entry carries a private key and the ARN naming one. Nothing logs
// an entry today, so this asserts the guard itself: whatever first logs one must
// not be able to disclose either credential by accident.
func TestAppEntryConfig_LogValueOmitsKeyMaterial(t *testing.T) {
	const (
		privateKey = "-----BEGIN RSA PRIVATE KEY-----\nc3VwZXItc2VjcmV0\n-----END RSA PRIVATE KEY-----"
		arn        = "arn:aws:kms:ap-southeast-2:123456789012:key/super-secret-key-id"
	)

	tests := []struct {
		name              string
		entry             appEntryConfig
		expectedKeySource string
		secrets           []string
	}{
		{
			name: "inline key",
			entry: appEntryConfig{
				Name:           "packages",
				ApplicationID:  333,
				InstallationID: 444,
				PrivateKey:     privateKey,
			},
			expectedKeySource: "privateKey",
			secrets:           []string{"c3VwZXItc2VjcmV0"},
		},
		{
			name: "KMS-backed key",
			entry: appEntryConfig{
				Name:           "packages",
				ApplicationID:  333,
				InstallationID: 444,
				PrivateKeyARN:  arn,
			},
			expectedKeySource: "privateKeyArn",
			secrets:           []string{arn, "123456789012", "super-secret-key-id"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))

			logger.Info("entry", "app", tt.entry)
			logged := buf.String()

			for _, secret := range tt.secrets {
				assert.NotContains(t, logged, secret)
			}

			// A record naming nothing is not actionable, so the
			// non-credential fields must survive the redaction.
			require.Contains(t, logged, `"name":"packages"`)
			assert.Contains(t, logged, `"applicationID":333`)
			assert.Contains(t, logged, `"installationID":444`)
			assert.Contains(t, logged, `"keySource":"`+tt.expectedKeySource+`"`)
		})
	}
}

// A malformed GITHUB_APPS entry is reported to the operator's startup log, so
// the decoder must never quote the value it choked on. json/v2 reports a type
// and a JSON pointer rather than a value; this pins that, because the guard is
// the library's behaviour rather than anything this package enforces.
func TestParseAppEntries_ErrorsNeverQuoteTheKey(t *testing.T) {
	const (
		pem    = "-----BEGIN RSA PRIVATE KEY-----c3VwZXItc2VjcmV0-----END RSA PRIVATE KEY-----"
		canary = "c3VwZXItc2VjcmV0"
	)

	tests := []struct {
		name string
		raw  string
	}{
		{"key where a number belongs", `[{"name":"a","appId":"` + pem + `","installationId":1}]`},
		{"key in an unknown member", `[{"name":"a","appId":1,"installationId":1,"privateKeyy":"` + pem + `"}]`},
		{"key in a duplicated member", `[{"name":"a","appId":1,"installationId":1,"privateKey":"` + pem + `","privateKey":"x"}]`},
		{"truncated mid-key", `[{"name":"a","appId":1,"installationId":1,"privateKey":"` + pem},
		{"unescaped newline in key", `[{"name":"a","appId":1,"installationId":1,"privateKey":"` + pem + "\n" + `"}]`},
		{"trailing document after key", `[{"name":"a","appId":1,"installationId":1,"privateKey":"` + pem + `"}] {"x":1}`},
		{"object where an array belongs", `{"name":"a","appId":1,"installationId":1,"privateKey":"` + pem + `"}`},
		{"key as the whole document", `"` + pem + `"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseAppEntries(tt.raw)

			require.Error(t, err)
			assert.NotContains(t, err.Error(), canary)
			assert.NotContains(t, err.Error(), "BEGIN RSA")
		})
	}
}

// LogValue guards slog, but fmt consults Stringer instead, so a format string
// anywhere would otherwise print the key. %#v is excluded by design: it renders
// Go syntax, and no production path formats a configuration entry that way.
func TestPrivateKeyPEM_RedactsUnderFmt(t *testing.T) {
	const canary = "c3VwZXItc2VjcmV0"

	entry := appEntryConfig{
		Name:           "packages",
		ApplicationID:  333,
		InstallationID: 444,
		PrivateKey:     "-----BEGIN RSA PRIVATE KEY-----" + canary + "-----END RSA PRIVATE KEY-----",
	}

	for _, verb := range []string{"%v", "%+v", "%s", "%q", "%#v"} {
		t.Run("entry "+verb, func(t *testing.T) {
			assert.NotContains(t, fmt.Sprintf(verb, entry), canary)
		})

		// The field travelling alone: a String method on the struct would not
		// reach this, which is why the redaction lives on the field's type.
		t.Run("key alone "+verb, func(t *testing.T) {
			assert.NotContains(t, fmt.Sprintf(verb, entry.PrivateKey), canary)
		})
	}

	t.Run("wrapped in an error", func(t *testing.T) {
		err := fmt.Errorf("app %q: %v", entry.Name, entry)

		assert.NotContains(t, err.Error(), canary)
		assert.True(t, strings.Contains(err.Error(), "packages"))
	})
}
