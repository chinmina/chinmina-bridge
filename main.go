package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
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

	vendorCache := vendor.Cached(tokenCache, orgProfile)

	// Pipeline routes use repoVendor (defaults to "default" profile)
	// The bare (non-profile) routes are for backward compatibility
	repoVendor := vendor.Auditor(vendorCache(vendor.NewRepoVendor(orgProfile, bk.RepositoryLookup, gh.CreateAccessToken)))
	pipelineTokenHandler := authorizedRouteMiddleware.Then(handlePostToken(repoVendor, profile.ProfileTypeRepo))
	mux.Handle("POST /token", pipelineTokenHandler)
	mux.Handle("POST /token/{profile}", pipelineTokenHandler)

	pipelineGitCredentialsHandler := authorizedRouteMiddleware.Then(handlePostGitCredentials(repoVendor, profile.ProfileTypeRepo))
	mux.Handle("POST /git-credentials", pipelineGitCredentialsHandler)
	mux.Handle("POST /git-credentials/{profile}", pipelineGitCredentialsHandler)

	// Organization routes use orgVendor (profile specified in path)
	orgVendor := vendor.Auditor(vendorCache(vendor.NewOrgVendor(orgProfile, gh.CreateAccessToken)))

	mux.Handle("POST /organization/token/{profile}", authorizedRouteMiddleware.Then(handlePostToken(orgVendor, profile.ProfileTypeOrg)))
	mux.Handle("POST /organization/git-credentials/{profile}", authorizedRouteMiddleware.Then(handlePostGitCredentials(orgVendor, profile.ProfileTypeOrg)))

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
	shutdownHooks := server.ShutdownHooks{}

	serverContext := context.Background()

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
	handler, err := configureServerRoutes(serverContext, cfg, orgProfile, &shutdownHooks)
	if err != nil {
		return fmt.Errorf("server routing configuration failed: %w", err)
	}

	orgProfileLocation := cfg.Server.OrgProfile

	taskCtx, cancel := context.WithCancel(serverContext)
	defer cancel()

	// Start Goroutine to refresh the organization profile every 5 minutes
	if orgProfileLocation != "" {
		// Check that the profile conforms to the expected format
		location := strings.SplitN(orgProfileLocation, ":", 3)
		if len(location) != 3 {
			return fmt.Errorf("invalid organization profile location: %s", orgProfileLocation)
		}

		gh, err := github.New(serverContext, cfg.Github, github.WithTokenTransport)
		if err != nil {
			return fmt.Errorf("github configuration failed: %w", err)
		}

		go profile.PeriodicRefresh(taskCtx, orgProfile, gh, orgProfileLocation)
	}

	// start the server
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:           handler,
		MaxHeaderBytes:    20 << 10,         // 20 KB
		ReadHeaderTimeout: 20 * time.Second, // Prevent Slowloris attacks
	}

	// cancelling the task context has to be the last action so it doesn't
	// interfere with other shutdown tasks. Cancel is done here explicitly to
	// include it with the rest of the shutdown hooks, even though it is deferred.
	shutdownHooks.Add("context", func() error { cancel(); return nil })
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
