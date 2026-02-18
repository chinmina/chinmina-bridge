package jwt

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/justinas/alice"
	"github.com/lestrrat-go/jwx/v3/jwk"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/config"
)

// Middleware returns HTTP middleware that verifies the JWT and
// enforces the validity claims. The retrieved claims are set on the request
// context and can be retrieved by calling jwt.ClaimsFromContext(ctx).
func Middleware(cfg config.AuthorizationConfig, options ...jwtmiddleware.Option) (func(http.Handler) http.Handler, error) {
	// allow for static configuration when testing
	jwksConfig := remoteJWKS
	if cfg.ConfigurationStatic != "" {
		jwksConfig = staticJWKS
	}

	url, keyFunc, err := jwksConfig(cfg)
	if err != nil {
		return nil, err
	}

	// the validator is used by the middleware to check the JWT signature and claims
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.RS256), // Buildkite only uses RSA at present
		validator.WithIssuer(url.String()),
		validator.WithAudience(cfg.Audience),
		validator.WithAllowedClockSkew(5*time.Second), // this could be configurable
		validator.WithCustomClaims(
			buildkiteCustomClaims(cfg.BuildkiteOrganizationSlug),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to set up the validator: %w", err)
	}

	// Auditing of the validation process uses a combination of the error handler
	// and the audit middleware. The first ensures that validation errors are marked in
	// the audit log, while the second ensures that the claims are logged when the
	// token is valid.

	// enable the use of the audit error handler and pass the validator
	options = append(options,
		jwtmiddleware.WithErrorHandler(auditErrorHandler()),
		jwtmiddleware.WithValidator(jwtValidator),
	)

	middleware, err := jwtmiddleware.New(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT middleware: %w", err)
	}

	validationMiddleware := middleware.CheckJWT

	subChain := alice.New(validationMiddleware, auditClaimsMiddleware()).Then

	return subChain, nil
}

type claimsContextKey struct{}

// ContextWithClaims returns a new context.Context with the provided validated claims
// added to it. This is primarily for test usage
func ContextWithClaims(ctx context.Context, claims *validator.ValidatedClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ContextWithBuildkiteClaims creates a context with BuildkiteClaims for testing.
// This is a convenience helper for tests that need to set up claim-based contexts.
func ContextWithBuildkiteClaims(ctx context.Context, claims *BuildkiteClaims) context.Context {
	return ContextWithClaims(ctx, &validator.ValidatedClaims{
		RegisteredClaims: validator.RegisteredClaims{},
		CustomClaims:     claims,
	})
}

// ClaimsFromContext returns the validated claims from the context as set by the
// JWT middleware. This will return nil if the context data is not set. This
// should be regarded as an error for handlers that expect the claims to be
// present.
func ClaimsFromContext(ctx context.Context) *validator.ValidatedClaims {
	// Production: v3 middleware stores claims internally
	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](ctx)
	if err == nil {
		return claims
	}
	// Test fallback: local key injection
	claims, _ = ctx.Value(claimsContextKey{}).(*validator.ValidatedClaims)
	return claims
}

// BuildkiteClaimsFromContext gets the custom Buildkite claims from the context, as added by the JWT
// middleware. This will return nil if the claims are not present.
func BuildkiteClaimsFromContext(ctx context.Context) *BuildkiteClaims {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return nil
	}

	bkClaims, _ := claims.CustomClaims.(*BuildkiteClaims)

	return bkClaims
}

func RequireBuildkiteClaimsFromContext(ctx context.Context) BuildkiteClaims {
	c := BuildkiteClaimsFromContext(ctx)
	if c == nil {
		panic("Buildkite claims not present in context, likely used outside of the JWT middleware")
	}

	return *c
}

func auditClaimsMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entry := audit.Log(r.Context())
			claims := ClaimsFromContext(r.Context())

			if claims == nil {
				entry.Error = "JWT claims missing from context"
			} else {
				reg := claims.RegisteredClaims
				entry.Authorized = true
				entry.AuthSubject = reg.Subject
				entry.AuthIssuer = reg.Issuer
				entry.AuthAudience = reg.Audience
				entry.AuthExpirySecs = reg.Expiry

				// Populate Buildkite identity fields from custom claims
				bkClaims := BuildkiteClaimsFromContext(r.Context())
				if bkClaims != nil {
					entry.OrganizationSlug = bkClaims.OrganizationSlug
					entry.PipelineSlug = bkClaims.PipelineSlug
					entry.JobID = bkClaims.JobID
					entry.BuildNumber = bkClaims.BuildNumber
					entry.BuildBranch = bkClaims.BuildBranch

					// Set span attributes for observability
					span := trace.SpanFromContext(r.Context())
					span.SetAttributes(
						attribute.String("buildkite.organization_slug", bkClaims.OrganizationSlug),
						attribute.String("buildkite.pipeline_slug", bkClaims.PipelineSlug),
						attribute.String("buildkite.job_id", bkClaims.JobID),
						attribute.Int("buildkite.build_number", bkClaims.BuildNumber),
						attribute.String("buildkite.build_branch", bkClaims.BuildBranch),
					)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func auditErrorHandler() jwtmiddleware.ErrorHandler {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		entry := audit.Log(r.Context())
		entry.Error = fmt.Sprintf("JWT authorization failure: %s", err.Error())

		// The default error handler will write the appropriate response status
		// code. The status code is recorded centrally by the central audit
		// middleware.
		jwtmiddleware.DefaultErrorHandler(w, r, err)
	}
}

type KeyFunc = func(ctx context.Context) (any, error)

func remoteJWKS(cfg config.AuthorizationConfig) (url.URL, KeyFunc, error) {
	issuerURL, err := url.Parse(cfg.IssuerURL)
	if err != nil {
		return url.URL{}, nil, fmt.Errorf("failed to parse the issuer URL: %w", err)
	}

	provider, err := jwks.NewCachingProvider(
		jwks.WithIssuerURL(issuerURL),
		jwks.WithCacheTTL(5*time.Minute),
	)
	if err != nil {
		return url.URL{}, nil, fmt.Errorf("failed to create JWKS provider: %w", err)
	}

	return *issuerURL, provider.KeyFunc, nil
}

func staticJWKS(cfg config.AuthorizationConfig) (url.URL, KeyFunc, error) {
	issuerURL, err := url.Parse(cfg.IssuerURL)
	if err != nil {
		return url.URL{}, nil, fmt.Errorf("failed to parse the issuer URL: %w", err)
	}

	jwks, err := jwk.Parse([]byte(cfg.ConfigurationStatic))
	if err != nil {
		return url.URL{}, nil, fmt.Errorf("could not decode jwks: %w", err)
	}

	keyFunc := func(_ context.Context) (any, error) { return jwks, nil }

	return *issuerURL, keyFunc, nil
}
