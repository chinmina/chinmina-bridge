package main

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

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/buildkite"
	"github.com/chinmina/chinmina-bridge/internal/cache"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/observe"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/server"
	"github.com/chinmina/chinmina-bridge/internal/vendor"

	"github.com/justinas/alice"
	phuslog "github.com/phuslu/log"
)

func configureServerRoutes(ctx context.Context, cfg config.Config, orgProfile *profile.ProfileStore, hooks *server.ShutdownHooks) (http.Handler, error) {
	// wrap a mux such that HTTP telemetry is configured by default
	muxWithoutTelemetry := http.NewServeMux()
	mux := observe.NewMux(muxWithoutTelemetry)

	// configure middleware
	auditor := audit.Middleware()

	authorizer, err := jwt.Middleware(cfg.Authorization)
	if err != nil {
		return nil, fmt.Errorf("authorizer configuration failed: %w", err)
	}

	// The request body size is fairly limited to prevent accidental or
	// deliberate abuse. Given the current API shape, this is not configurable.
	requestLimitBytes := int64(20 << 10) // 20 KB
	requestLimiter := maxRequestSize(requestLimitBytes)

	// When a base path is configured, strip it before routing so the
	// application can be served under a sub-path (e.g. behind an ALB).
	normalizedBasePath, err := config.NormalizeBasePath(cfg.Server.BasePath)
	if err != nil {
		return nil, fmt.Errorf("invalid base path: %w", err)
	}

	if normalizedBasePath != "" {
		slog.Info("serving under base path", "path", normalizedBasePath)
	}

	authorizedRouteMiddleware := alice.New(requestLimiter, auditor, authorizer)
	standardRouteMiddleware := alice.New(requestLimiter)

	// setup token handler and dependencies
	bk, err := buildkite.New(cfg.Buildkite)
	if err != nil {
		return nil, fmt.Errorf("buildkite configuration failed: %w", err)
	}

	gh, err := github.New(ctx, cfg.Github)
	if err != nil {
		return nil, fmt.Errorf("github configuration failed: %w", err)
	}

	// Configure cache backend based on CACHE_TYPE
	tokenCache, err := cache.NewFromConfig[vendor.ProfileToken](
		ctx,
		cfg.Cache,
		45*time.Minute,
		10_000,
	)
	if err != nil {
		return nil, fmt.Errorf("cache configuration failed: %w", err)
	}

	hooks.Add("cache", tokenCache.Close)

	// Pipeline and organization routes are deliberately separate, with very
	// different authorization and match rules. This allows for simpler controls
	// on the request path, as the types are differentiated by construction
	// instead of runtime checks.
	//
	// Within their type, each vendor chain has the same flow:
	//   Audit -> Resolve Profile -> Authorize -> Cache -> Token Vendor
	//
	// The profile is resolved once, at the handler boundary, and the resolved
	// value is carried through the chain. The underlying cache is
	// shared by both vendor chains, sharing contents, TTL and capacity.

	// Pipeline (repo) routes

	repoVendor := vendor.Auditor(
		vendor.Authorized(
			vendor.Cached[profile.PipelineProfileAttr](tokenCache)(
				vendor.Vending(vendor.PipelineRepositories(bk.RepositoryLookup), gh.CreateAccessToken),
			),
		),
	)

	pipelineResolver := NewPipelineProfileResolver(orgProfile.GetPipelineProfile)
	pipelineTokenHandler := authorizedRouteMiddleware.Then(handlePostToken(repoVendor, pipelineResolver))
	mux.Handle("POST /token", pipelineTokenHandler)
	mux.Handle("POST /token/{profile}", pipelineTokenHandler)

	pipelineGitCredentialsHandler := authorizedRouteMiddleware.Then(handlePostGitCredentials(repoVendor, pipelineResolver))
	mux.Handle("POST /git-credentials", pipelineGitCredentialsHandler)
	mux.Handle("POST /git-credentials/{profile}", pipelineGitCredentialsHandler)

	// Organization routes

	orgVendor := vendor.Auditor(
		vendor.Authorized(
			vendor.Cached[profile.OrganizationProfileAttr](tokenCache)(
				vendor.Vending(vendor.OrgRepositories, gh.CreateAccessToken),
			),
		),
	)

	orgResolver := NewOrgProfileResolver(orgProfile.GetOrganizationProfile)
	mux.Handle("POST /organization/token/{profile}", authorizedRouteMiddleware.Then(handlePostToken(orgVendor, orgResolver)))
	mux.Handle("POST /organization/git-credentials/{profile}", authorizedRouteMiddleware.Then(handlePostGitCredentials(orgVendor, orgResolver)))

	// healthchecks are not included in telemetry or authorization
	muxWithoutTelemetry.Handle("GET /healthcheck", standardRouteMiddleware.Then(handleHealthCheck()))

	// StripPrefix wraps the entire mux so it runs before pattern matching.
	var handler http.Handler = mux
	if normalizedBasePath != "" {
		handler = stripPrefix(normalizedBasePath, mux)
	}

	return handler, nil
}

func main() {
	configureLogging()

	logBuildInfo()

	err := launchServer()
	if err != nil {
		slog.Error("server failed to start", "error", err)
		os.Exit(1)
	}
}

func launchServer() error {
	return runWithShutdownHooks(context.Background(), startServer)
}

// runWithShutdownHooks guarantees that hooks registered by run are executed
// before the process exits, on whichever path it takes. Registration happens
// progressively during startup, so an exit before the HTTP server begins
// serving (a configuration failure, or any later startup gate) would otherwise
// discard buffered telemetry describing that very failure and leak the cache
// connection.
//
// The deferred call and the server's own shutdown wiring both call Execute;
// Execute runs the hooks at most once, so the two call sites cannot
// double-execute them.
func runWithShutdownHooks(ctx context.Context, run func(context.Context, *server.ShutdownHooks) error) error {
	shutdownHooks := &server.ShutdownHooks{}
	defer shutdownHooks.Execute(ctx)

	return run(ctx, shutdownHooks)
}

// startProfileRefresh blocks until the first profile generation loads.
//
// An instance serving without one answers organization profiles with 404 and
// pipelines with a built-in permission set, while reporting healthy to a
// rolling deployment. Not listening is the readiness signal, so gating before
// serveHTTP leaves the healthcheck contract alone.
//
// No timeout: a deadline of ours would be evidence about this service rather
// than the profile source, so the platform's grace period is the backstop.
//
// serverCtx builds the GitHub client and outlives shutdown; taskCtx governs the
// refresh task.
func startProfileRefresh(serverCtx, taskCtx context.Context, cfg config.Config, orgProfile *profile.ProfileStore) error {
	orgProfileLocation := cfg.Server.OrgProfile
	if orgProfileLocation == "" {
		return nil
	}

	err := profile.ValidateLocation(orgProfileLocation)
	if err != nil {
		return fmt.Errorf("invalid organization profile location: %w", err)
	}

	gh, err := github.New(serverCtx, cfg.Github, github.WithTokenTransport)
	if err != nil {
		return fmt.Errorf("github configuration failed: %w", err)
	}

	ready := profile.RefreshTask(orgProfile, gh, orgProfileLocation).Start(taskCtx)

	return awaitFirstLoad(taskCtx, ready)
}

// awaitFirstLoad treats cancellation as a startup failure: the instance never
// became ready, so it exits non-zero having run its hooks rather than being
// killed with its telemetry unflushed.
func awaitFirstLoad(ctx context.Context, ready <-chan struct{}) error {
	select {
	case <-ready:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("initial organization profile load abandoned: %w", ctx.Err())
	}
}

func startServer(serverContext context.Context, shutdownHooks *server.ShutdownHooks) error {
	orgProfile := profile.NewProfileStore()
	orgProfile.Update(serverContext, profile.NewDefaultProfiles())
	cfg, err := config.Load(serverContext)
	if err != nil {
		return fmt.Errorf("configuration load failed: %w", err)
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

	http.DefaultTransport = observe.HTTPTransport(
		configureHTTPTransport(cfg.Server),
		cfg.Observe,
	)
	http.DefaultClient = &http.Client{
		Transport: http.DefaultTransport,
	}

	// setup routing and dependencies
	handler, err := configureServerRoutes(serverContext, cfg, orgProfile, shutdownHooks)
	if err != nil {
		return fmt.Errorf("server routing configuration failed: %w", err)
	}

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

	err = startProfileRefresh(serverContext, taskCtx, cfg, orgProfile)
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

func configureHTTPTransport(cfg config.ServerConfig) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	transport.MaxIdleConns = cfg.OutgoingHTTPMaxIdleConns
	transport.MaxConnsPerHost = cfg.OutgoingHTTPMaxConnsPerHost

	return transport
}
