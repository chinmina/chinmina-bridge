// Package jwt validates Buildkite OIDC assertions and exposes validated claims
// to request handlers. Middleware verifies signatures and registered claims
// using remote or statically configured JWKS, validates Buildkite identity,
// and records authentication results in the request's audit entry.
//
// Authentication here is distinct from profile authorization: the profile and
// vendor packages decide what a validated identity may request. Claims access
// through RequireBuildkiteClaimsFromContext assumes the validation middleware
// has run; context injection helpers also support tests without an OIDC server.
package jwt
