package observe

import (
	"fmt"
	"log/slog"
	"runtime"

	pyroscope "github.com/grafana/pyroscope-go"

	"github.com/chinmina/chinmina-bridge/internal/config"
)

var experiment = ""

// ConfigurePyroscope starts the Pyroscope continuous profiling agent when
// enabled. Returns a stop function and a nil error on success, or a no-op
// stop function when profiling is disabled. The caller is responsible for
// calling the stop function on shutdown.
func ConfigurePyroscope(cfg config.ObserveConfig) (func() error, error) {
	if !cfg.PyroscopeEnabled {
		slog.Info("pyroscope profiling disabled: enable with OBSERVE_PYROSCOPE_ENABLED")
		return func() error { return nil }, nil
	}

	runtime.SetMutexProfileFraction(5)
	runtime.SetBlockProfileRate(5)

	tags := map[string]string{}

	// Runtime config takes precedence over the compile-time experiment tag.
	experimentTag := cfg.PyroscopeExperimentFlag
	if experimentTag == "" {
		experimentTag = experiment
	}
	if experimentTag != "" {
		tags["experiment"] = experimentTag
	}

	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: cfg.ServiceName,
		ServerAddress:   cfg.PyroscopeServerAddress,
		Tags:            tags,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileInuseObjects,
			pyroscope.ProfileInuseSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileMutexCount,
			pyroscope.ProfileMutexDuration,
			pyroscope.ProfileBlockCount,
			pyroscope.ProfileBlockDuration,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("pyroscope profiler startup failed: %w", err)
	}

	attrs := []any{"address", cfg.PyroscopeServerAddress}
	if experimentTag != "" {
		attrs = append(attrs, "experiment", experimentTag)
	}
	slog.Info("pyroscope continuous profiling started", attrs...)

	return profiler.Stop, nil
}
