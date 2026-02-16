//go:build integration

package testhelpers

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// RunValkeyContainer starts a Valkey container and returns the configuration
// including the ephemeral address and password. Cleanup is handled
// automatically via t.Cleanup().
func RunValkeyContainer(t *testing.T) config.CacheConfig {
	t.Helper()
	ctx := context.Background()

	valkeyPort := "6379"
	valkeyProtocolPort := valkeyPort + "/tcp"

	password := rand.Text()

	req := testcontainers.ContainerRequest{
		Image: "valkey/valkey:9-alpine",
		Env: map[string]string{
			"VALKEY_EXTRA_FLAGS": "--requirepass " + password,
		},
		ExposedPorts: []string{valkeyProtocolPort},
		WaitingFor: wait.ForAll(
			wait.ForLog("Ready to accept connections"),
			wait.ForListeningPort(nat.Port(valkeyProtocolPort)),
		),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           log.TestLogger(t),
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	port, err := container.MappedPort(ctx, nat.Port(valkeyPort))
	require.NoError(t, err)

	// Use 127.0.0.1 explicitly to avoid IPv6 issues
	endpoint := "127.0.0.1:" + port.Port()

	// Generate a cleartext keyset file for integration test encryption.
	keysetFile := writeTestKeyset(t)

	return config.CacheConfig{
		Type: "valkey",
		Valkey: config.ValkeyConfig{
			TLS:      false,
			Address:  endpoint,
			Username: "default",
			Password: password,
		},
		Encryption: config.CacheEncryptionConfig{
			Enabled:    true,
			KeysetFile: keysetFile,
		},
	}
}

// writeTestKeyset generates an AES256-GCM Tink keyset and writes it as
// cleartext JSON to a temp file. The file is cleaned up automatically via
// t.TempDir().
func writeTestKeyset(t *testing.T) string {
	t.Helper()

	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	keysetPath := filepath.Join(t.TempDir(), "test-keyset.json")
	f, err := os.Create(keysetPath)
	require.NoError(t, err)
	defer f.Close()

	err = insecurecleartextkeyset.Write(handle, keyset.NewJSONWriter(f))
	require.NoError(t, err)

	return keysetPath
}
