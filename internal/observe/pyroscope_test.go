package observe

import (
	"runtime"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigurePyroscope_Disabled(t *testing.T) {
	cfg := config.ObserveConfig{
		PyroscopeEnabled: false,
	}

	stop, err := ConfigurePyroscope(cfg)
	require.NoError(t, err)
	require.NotNil(t, stop)
	assert.NoError(t, stop())
}

func TestConfigurePyroscope_Disabled_NoSideEffects(t *testing.T) {
	// The enabled path sets mutex and block profile rates. Verify the disabled
	// path leaves them unchanged so profiling overhead is not incurred unless
	// Pyroscope is intentionally enabled.
	before := runtime.SetMutexProfileFraction(-1) // -1 reads without changing

	cfg := config.ObserveConfig{
		PyroscopeEnabled: false,
	}
	_, _ = ConfigurePyroscope(cfg)

	after := runtime.SetMutexProfileFraction(-1)
	assert.Equal(t, before, after, "disabled path must not change mutex profile fraction")
}
