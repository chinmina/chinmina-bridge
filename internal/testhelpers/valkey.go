//go:build integration

package testhelpers

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"
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

	return config.CacheConfig{
		Type: "valkey",
		Valkey: config.ValkeyConfig{
			TLS:      false,
			Address:  endpoint,
			Username: "default",
			Password: password,
		},
	}
}
