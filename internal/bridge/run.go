package bridge

import (
	"context"
	"fmt"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/buildkite"
	"github.com/chinmina/chinmina-bridge/internal/cache"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/server"
	"github.com/chinmina/chinmina-bridge/internal/vendor"

	"github.com/justinas/alice"
)

type validatedConfig struct {
	basePath           string // "" when served at the root
	orgProfileLocation string // "" when no organization profile is configured
	authorizer         alice.Constructor

	// The bool stops here: route construction receives a marshaller instead.
	discloseAppIdentifiers bool
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
		basePath:               basePath,
		orgProfileLocation:     orgProfileLocation,
		authorizer:             authorizer,
		discloseAppIdentifiers: cfg.Development.DiscloseAppIdentifiers,
	}, nil
}

// upstreamClients must not be replaced after route construction captures it:
// the handlers would keep the old values.
type upstreamClients struct {
	buildkite buildkite.PipelineLookup

	// apps is the authority on which GitHub App a profile mints through. It
	// includes the default app, so single-app deployments take the same path as
	// multi-app ones.
	apps github.Registry

	// Token rather than app transport, because it reads repository content.
	// Nil when unconfigured, which is what leaves the refresh task unstarted.
	//
	// Always the default app: the profile configuration selects each profile's
	// app, so reading that configuration through a selected app is circular.
	profileSource *github.Client

	tokenCache cache.TokenCache[vendor.ProfileToken]
}

// configureUpstreamClients must run after installOutboundTransport: clients
// capture http.DefaultTransport as they are built, so one made earlier
// silently loses pool tuning and tracing. Add new clients here.
func configureUpstreamClients(ctx context.Context, cfg config.Config, validated validatedConfig, hooks *server.ShutdownHooks) (upstreamClients, error) {
	bk, err := buildkite.New(cfg.Buildkite)
	if err != nil {
		return upstreamClients{}, fmt.Errorf("buildkite configuration failed: %w", err)
	}

	gh, err := github.New(ctx, cfg.Github)
	if err != nil {
		return upstreamClients{}, fmt.Errorf("github configuration failed: %w", err)
	}

	// ctx must be the long-lived server context: it reaches KMS signing key
	// construction, and a key built under a shorter-lived one boots cleanly
	// then fails every mint once that context expires.
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
