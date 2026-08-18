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

type validatedConfig struct {
	basePath           string // "" when served at the root
	orgProfileLocation string // "" when no organization profile is configured
	authorizer         alice.Constructor
}

// validateConfiguration must not make network calls, so that a configuration
// error always beats the connectivity failure that would otherwise mask it.
func validateConfiguration(cfg config.Config) (validatedConfig, error) {
	// When a base path is configured, it is stripped before routing so the
	// application can be served under a sub-path (e.g. behind an ALB).
	basePath, err := config.NormalizeBasePath(cfg.Server.BasePath)
	if err != nil {
		return validatedConfig{}, fmt.Errorf("invalid base path: %w", err)
	}

	// Empty disables organization profiles. Checking here rather than at the
	// gate is what keeps a typo cheap to diagnose.
	orgProfileLocation := cfg.Server.OrgProfile
	if orgProfileLocation != "" {
		if err := profile.ValidateLocation(orgProfileLocation); err != nil {
			return validatedConfig{}, fmt.Errorf("invalid organization profile location: %w", err)
		}
	}

	authorizer, err := jwt.Middleware(cfg.Authorization)
	if err != nil {
		return validatedConfig{}, fmt.Errorf("authorizer configuration failed: %w", err)
	}

	return validatedConfig{
		basePath:           basePath,
		orgProfileLocation: orgProfileLocation,
		authorizer:         authorizer,
	}, nil
}

// upstreamClients must not be replaced after route construction captures it:
// the handlers would keep the old values.
type upstreamClients struct {
	buildkite buildkite.PipelineLookup

	// apps is the authority on which GitHub App a profile mints through. It
	// includes the default app, so single-app deployments go through the same
	// path as multi-app ones and there is no untested second code path.
	apps github.Registry

	// Token rather than app transport, because it reads repository content.
	// Nil when unconfigured, which is what leaves the refresh task unstarted.
	//
	// Always the default app: the profile configuration decides which app a
	// profile uses, so reading it through a profile-selected app would be
	// circular.
	profileSource *github.Client

	tokenCache cache.TokenCache[vendor.ProfileToken]
}

// configureUpstreamClients must run after installOutboundTransport: clients
// capture http.DefaultTransport as they are built, so one made earlier
// silently loses pool tuning and tracing. That applies to the app registry's
// clients too — built here, after the transport is installed, so registry
// traffic is traced and pool-tuned like everything else. Add new clients here.
func configureUpstreamClients(ctx context.Context, cfg config.Config, validated validatedConfig, hooks *server.ShutdownHooks) (upstreamClients, error) {
	bk, err := buildkite.New(cfg.Buildkite)
	if err != nil {
		return upstreamClients{}, fmt.Errorf("buildkite configuration failed: %w", err)
	}

	gh, err := github.New(ctx, cfg.Github)
	if err != nil {
		return upstreamClients{}, fmt.Errorf("github configuration failed: %w", err)
	}

	// ctx is the long-lived server context by contract: it reaches KMS signing
	// key construction, and a key built under a shorter-lived context boots
	// cleanly and then fails every mint once that context expires.
	apps, err := github.NewRegistry(ctx, cfg.Github, gh)
	if err != nil {
		return upstreamClients{}, fmt.Errorf("github app registry configuration failed: %w", err)
	}

	var profileSource *github.Client
	if validated.orgProfileLocation != "" {
		client, err := github.New(ctx, cfg.Github, github.WithTokenTransport)
		if err != nil {
			return upstreamClients{}, fmt.Errorf("github configuration failed: %w", err)
		}
		profileSource = &client
	}

	// Configure cache backend based on CACHE_TYPE
	tokenCache, err := cache.NewFromConfig[vendor.ProfileToken](
		ctx,
		cfg.Cache,
		45*time.Minute,
		10_000,
	)
	if err != nil {
		return upstreamClients{}, fmt.Errorf("cache configuration failed: %w", err)
	}

	hooks.Add("cache", tokenCache.Close)

	return upstreamClients{
		buildkite:     bk,
		apps:          apps,
		profileSource: profileSource,
		tokenCache:    tokenCache,
	}, nil
}

// configureServerRoutes cannot fail: everything it needs is validated and
// constructed before it is called.
func configureServerRoutes(validated validatedConfig, clients upstreamClients, orgProfile *profile.ProfileStore) http.Handler {
	// wrap a mux such that HTTP telemetry is configured by default
	muxWithoutTelemetry := http.NewServeMux()
	mux := observe.NewMux(muxWithoutTelemetry)

	// configure middleware
	auditor := audit.Middleware()

	// The request body size is fairly limited to prevent accidental or
	// deliberate abuse. Given the current API shape, this is not configurable.
	requestLimitBytes := int64(20 << 10) // 20 KB
	requestLimiter := maxRequestSize(requestLimitBytes)

	if validated.basePath != "" {
		slog.Info("serving under base path", "path", validated.basePath)
	}

	authorizedRouteMiddleware := alice.New(requestLimiter, auditor, validated.authorizer)
	standardRouteMiddleware := alice.New(requestLimiter)

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

	// Vending mints through whichever app the request resolved to. The
	// registry is passed as a minting function rather than resolved per
	// request inside the chain: Cached short-circuits before Vending runs, so
	// the resolution that guards a warm entry has to happen in the resolver.
	mint := clients.apps.CreateAccessToken
	resolveApp := clients.apps.Resolve

	repoVendor := vendor.Auditor(
		vendor.Authorized(
			vendor.Cached[profile.PipelineProfileAttr](clients.tokenCache)(
				vendor.Vending(vendor.PipelineRepositories(clients.buildkite.RepositoryLookup), mint),
			),
		),
	)

	pipelineResolver := NewPipelineProfileResolver(orgProfile.GetPipelineProfile, resolveApp)
	pipelineTokenHandler := authorizedRouteMiddleware.Then(handlePostToken(repoVendor, pipelineResolver))
	mux.Handle("POST /token", pipelineTokenHandler)
	mux.Handle("POST /token/{profile}", pipelineTokenHandler)

	pipelineGitCredentialsHandler := authorizedRouteMiddleware.Then(handlePostGitCredentials(repoVendor, pipelineResolver))
	mux.Handle("POST /git-credentials", pipelineGitCredentialsHandler)
	mux.Handle("POST /git-credentials/{profile}", pipelineGitCredentialsHandler)

	// Organization routes

	orgVendor := vendor.Auditor(
		vendor.Authorized(
			vendor.Cached[profile.OrganizationProfileAttr](clients.tokenCache)(
				vendor.Vending(vendor.OrgRepositories, mint),
			),
		),
	)

	orgResolver := NewOrgProfileResolver(orgProfile.GetOrganizationProfile, resolveApp)
	mux.Handle("POST /organization/token/{profile}", authorizedRouteMiddleware.Then(handlePostToken(orgVendor, orgResolver)))
	mux.Handle("POST /organization/git-credentials/{profile}", authorizedRouteMiddleware.Then(handlePostGitCredentials(orgVendor, orgResolver)))

	// healthchecks are not included in telemetry or authorization
	muxWithoutTelemetry.Handle("GET /healthcheck", standardRouteMiddleware.Then(handleHealthCheck()))

	// StripPrefix wraps the entire mux so it runs before pattern matching.
	var handler http.Handler = mux
	if validated.basePath != "" {
		handler = stripPrefix(validated.basePath, mux)
	}

	return handler
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
func startProfileRefresh(taskCtx context.Context, orgProfile *profile.ProfileStore, source *github.Client, location string, usableApp profile.AppLookup) error {
	if source == nil {
		return nil
	}

	ready := profile.RefreshTask(orgProfile, *source, location, usableApp).Start(taskCtx)

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
