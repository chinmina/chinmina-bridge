package observe

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/resource"
)

func Test_configuredExporters(t *testing.T) {
	tests := []struct {
		name         string
		observeType  string
		expectedType exporters
	}{
		{"grpc", "grpc", grpcExporters{}},
		{"stdout", "stdout", stdoutExporters{}},
		{"http", "http", httpExporters{}},
		{"unknown defaults to grpc", "unknown", grpcExporters{}},
		{"empty defaults to grpc", "", grpcExporters{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.ObserveConfig{Type: tt.observeType}
			result := configuredExporters(cfg)
			assert.IsType(t, tt.expectedType, result)
		})
	}
}

func Test_ResourceMerge(t *testing.T) {
	// Ensure that schema incompatibility on OTEL upgrades is detected before
	// merge
	_, err := resourceWithServiceName(
		resource.Default(),
		"serviceName")

	require.NoError(t, err)
}
