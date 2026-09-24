package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/observe"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/server"

	phuslog "github.com/phuslu/log"
)

// Run starts the bridge service and blocks until it has shut down. Logging is
// configured here rather than by the caller, so that only the service path
// pays for it.
//
// ctx must be long-lived: it reaches KMS signing key construction, and must
// not be cancelled by shutdown signals (see startServer).
func Run(ctx context.Context) error {
	configureLogging()

	logBuildInfo()

	return runWithShutdownHooks(ctx, startServer)
}

// startServer's stage order is load-bearing; each stage documents its own
// constraint. Data flow enforces most of them, but telemetry-before-transport
// holds only while these calls stay in this order.
func startServer(serverContext context.Context, shutdownHooks *server.ShutdownHooks) error {
	orgProfile := profile.NewProfileStore()
	orgProfile.Update(serverContext, profile.NewDefaultProfiles())

	cfg, err := config.Load(serverContext)
	if err != nil {
		return fmt.Errorf("configuration load failed: %w", err)
	}

	validated, err := validateConfiguration(cfg)
	if err != nil {
		return err
	}

	// configure telemetry, including wrapping default HTTP client
	shutdownTelemetry, err := observe.Configure(serverContext, cfg.Observe)
	if err != nil {
		return fmt.Errorf("telemetry bootstrap failed: %w", err)
	}
	shutdownHooks.AddContext("telemetry", shutdownTelemetry)

	// Pyroscope must start after OTel: otelpyroscope.NewTracerProvider (in
	// Configure above) wraps the OTel tracer provider to correlate profiles with
	// traces. Shutdown order is FIFO, so telemetry flushes spans first, then
	// Pyroscope stops — which is also correct.
	downPyroscope, err := observe.ConfigurePyroscope(cfg.Observe)
	if err != nil {
		return fmt.Errorf("pyroscope profiler configuration failed: %w", err)
	}
	shutdownHooks.Add("pyroscope", downPyroscope)

	installOutboundTransport(cfg)

	clients, err := configureUpstreamClients(serverContext, cfg, validated, shutdownHooks)
	if err != nil {
		return err
	}

	handler := configureServerRoutes(validated, clients, orgProfile)

	// Signal-aware because the gate below can block indefinitely, and
	// serveHTTP — which installs the serving path's handler — is not reached
	// until it opens. Without this, a SIGTERM while waiting kills the process
	// before the hooks can flush the telemetry explaining the wait.
	//
	// Only taskCtx: serverContext builds the GitHub clients, and cancelling it
	// would break minting for requests still in flight during shutdown.
	taskCtx, stop := signal.NotifyContext(serverContext, syscall.SIGINT, syscall.SIGTERM)

	// Cancelling the task context has to be the last action so it doesn't
	// interfere with other shutdown tasks, so it is registered here rather than
	// deferred: the hooks are the only cancellation path, and they now run on
	// every exit from startup, not just once the server is serving.
	shutdownHooks.Add("context", func() error { stop(); return nil })

	err = startProfileRefresh(taskCtx, orgProfile, clients.profileSource, validated.orgProfileLocation, clients.apps.IsUsable)
	if err != nil {
		return err
	}

	// start the server
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:           handler,
		MaxHeaderBytes:    20 << 10,         // 20 KB
		ReadHeaderTimeout: 20 * time.Second, // Prevent Slowloris attacks
	}

	server.RegisterOnShutdown(func() {
		shutdownHooks.Execute(serverContext)
	})

	err = serveHTTP(cfg.Server, server)
	if err != nil {
		return fmt.Errorf("server failed: %w", err)
	}

	return nil
}

func configureLogging() {
	var handler slog.Handler
	if os.Getenv("ENV") == "development" {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
	} else {
		// phuslu/log provides lower mutex contention and fewer allocations than the
		// stdlib slog handler. This significantly reduces the wait times seen in
		// higher throughput benchmarks.
		handler = phuslog.SlogNewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
	}

	slog.SetDefault(slog.New(handler))
}

func logBuildInfo() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	var attrs []any
	for _, v := range buildInfo.Settings {
		if strings.HasPrefix(v.Key, "vcs.") ||
			strings.HasPrefix(v.Key, "GO") ||
			v.Key == "CGO_ENABLED" {
			attrs = append(attrs, v.Key, v.Value)
		}
	}

	slog.Info("build information", attrs...)
}

// installOutboundTransport must run after telemetry is configured: the tracing
// wrapper binds the providers set up there.
func installOutboundTransport(cfg config.Config) {
	http.DefaultTransport = observe.HTTPTransport(
		configureHTTPTransport(cfg.Server),
		cfg.Observe,
	)
	http.DefaultClient = &http.Client{
		Transport: http.DefaultTransport,
	}
}

func configureHTTPTransport(cfg config.ServerConfig) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	transport.MaxIdleConns = cfg.OutgoingHTTPMaxIdleConns
	transport.MaxConnsPerHost = cfg.OutgoingHTTPMaxConnsPerHost

	return transport
}
