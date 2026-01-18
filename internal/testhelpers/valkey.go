//go:build integration

package testhelpers

import (
	"context"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"
)

// RunValkeyContainer starts a Valkey container and returns the address.
// Cleanup is handled automatically via t.Cleanup().
func RunValkeyContainer(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	valkeyPort := "6379"
	valkeyProtocolPort := valkeyPort + "/tcp"

	req := testcontainers.ContainerRequest{
		Image:        "valkey/valkey:8-alpine",
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

	return endpoint
}
