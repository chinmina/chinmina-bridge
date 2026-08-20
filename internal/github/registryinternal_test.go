package github

import (
	"bytes"
	"log/slog"
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
