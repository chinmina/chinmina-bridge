package main

import (
	"context"
	"fmt"
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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/justinas/alice"
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

	return mux, nil
}

func main() {
	configureLogging()

	logBuildInfo()

	err := launchServer()
	if err != nil {
		log.Fatal().Err(err).Msg("server failed to start")
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
	// Set global level to the minimum: allows the Open Telemetry logging to be
	// configured separately. However, it means that any logger that sets its
	// level will log as this effectively disables the global level.
	zerolog.SetGlobalLevel(zerolog.Level(-128))

	// default level is Info
	log.Logger = log.Level(zerolog.InfoLevel)

	if os.Getenv("ENV") == "development" {
		log.Logger = log.
			Output(zerolog.ConsoleWriter{Out: os.Stdout}).
			Level(zerolog.DebugLevel)
	}

	zerolog.DefaultContextLogger = &log.Logger
}

func logBuildInfo() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	ev := log.Info()
	for _, v := range buildInfo.Settings {
		if strings.HasPrefix(v.Key, "vcs.") ||
			strings.HasPrefix(v.Key, "GO") ||
			v.Key == "CGO_ENABLED" {
			ev = ev.Str(v.Key, v.Value)
		}
	}

	ev.Msg("build information")
}

func configureHTTPTransport(cfg config.ServerConfig) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	transport.MaxIdleConns = cfg.OutgoingHTTPMaxIdleConns
	transport.MaxConnsPerHost = cfg.OutgoingHTTPMaxConnsPerHost

	return transport
}
