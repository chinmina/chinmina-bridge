package bridge

import (
	"log/slog"
	"net/http"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/observe"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/justinas/alice"
)

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

	if validated.discloseAppIdentifiers {
		slog.Warn("github app identifiers are disclosed in token responses; development use only",
			"flag", "DEV_DISCLOSE_APP_IDENTIFIERS")
	}
	marshaler := newTokenResponseMarshaler(validated.discloseAppIdentifiers)

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
	pipelineTokenHandler := authorizedRouteMiddleware.Then(handlePostToken(repoVendor, pipelineResolver, marshaler))
	mux.Handle("POST /token", pipelineTokenHandler)
	mux.Handle("POST /token/{profile}", pipelineTokenHandler)

	pipelineGitCredentialsHandler := authorizedRouteMiddleware.Then(handlePostGitCredentials(repoVendor, pipelineResolver, marshaler))
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
	mux.Handle("POST /organization/token/{profile}", authorizedRouteMiddleware.Then(handlePostToken(orgVendor, orgResolver, marshaler)))
	mux.Handle("POST /organization/git-credentials/{profile}", authorizedRouteMiddleware.Then(handlePostGitCredentials(orgVendor, orgResolver, marshaler)))

	// healthchecks are not included in telemetry or authorization
	muxWithoutTelemetry.Handle("GET /healthcheck", standardRouteMiddleware.Then(handleHealthCheck()))

	// StripPrefix wraps the entire mux so it runs before pattern matching.
	var handler http.Handler = mux
	if validated.basePath != "" {
		handler = stripPrefix(validated.basePath, mux)
	}

	return handler
}
