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
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/observe"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/justinas/alice"
)

func configureServerRoutes(ctx context.Context, cfg config.Config, orgProfile *github.ProfileStore) (http.Handler, error) {
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

	vendorCache, err := vendor.Cached(45 * time.Minute)
	if err != nil {
		return nil, fmt.Errorf("vendor cache configuration failed: %w", err)
	}

	tokenVendor := vendor.Auditor(vendorCache(vendor.New(bk.RepositoryLookup, gh.CreateAccessToken, orgProfile)))

	mux.Handle("POST /token", authorizedRouteMiddleware.Then(handlePostToken(tokenVendor)))
	mux.Handle("POST /git-credentials", authorizedRouteMiddleware.Then(handlePostGitCredentials(tokenVendor)))

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
	orgProfile := github.NewProfileStore()
	ctx := context.Background()

	cfg, err := config.Load(context.Background())
	if err != nil {
		return fmt.Errorf("configuration load failed: %w", err)
	}

	// configure telemetry, including wrapping default HTTP client
	shutdownTelemetry, err := observe.Configure(ctx, cfg.Observe)
	if err != nil {
		return fmt.Errorf("telemetry bootstrap failed: %w", err)
	}

	http.DefaultTransport = observe.HttpTransport(
		configureHttpTransport(cfg.Server),
		cfg.Observe,
	)
	http.DefaultClient = &http.Client{
		Transport: http.DefaultTransport,
	}

	// setup routing and dependencies
	handler, err := configureServerRoutes(ctx, cfg, orgProfile)
	if err != nil {
		return fmt.Errorf("server routing configuration failed: %w", err)
	}

	// Start Goroutine to refresh the organization profile every 5 minutes.
	orgProfileURL := cfg.Server.OrgProfileURL

	if orgProfileURL != "" {
		// Separate GH client for the profile refresh
		gh, err := github.New(ctx, cfg.Github)
		if err != nil {
			return fmt.Errorf("github configuration failed: %w", err)
		}

		go refreshOrgProfile(ctx, orgProfile, gh, cfg.Server.OrgProfileURL)
	}

	// start the server
	server := &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:        handler,
		MaxHeaderBytes: 20 << 10, // 20 KB
	}

	server.RegisterOnShutdown(func() {
		log.Info().Msg("telemetry: shutting down")
		shutdownTelemetry(ctx)
		log.Info().Msg("telemetry: shutdown complete")
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

func configureHttpTransport(cfg config.ServerConfig) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	transport.MaxIdleConns = cfg.OutgoingHttpMaxIdleConns
	transport.MaxConnsPerHost = cfg.OutgoingHttpMaxConnsPerHost

	return transport
}

func refreshOrgProfile(ctx context.Context, profileStore *github.ProfileStore, gh github.Client, orgProfileURL string) {
	defer func() {
		if r := recover(); r != nil {
			log.Info().Interface("recover", r).Msg("background profile refresh failed; will attempt to continue.")
		}
	}()

	for {
		profileConfig, err := github.FetchOrganizationProfile(orgProfileURL, gh)
		if err != nil {
			// log the failure to fetch, then continue. This may be transient, so we
			// need to keep trying.
			log.Info().Err(err).Msg("organization profile refresh failed, continuing")
		} else {
			// only update the profile if retrieval succeeded
			profileStore.Update(&profileConfig)
		}

		select {
		case <-time.After(5 * time.Minute):
			// continue
		case <-ctx.Done():
			log.Info().Msg("refresh goroutine shutting down gracefully")
			return
		}
	}
}
