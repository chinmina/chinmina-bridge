// Package jwxtest provides test utilities for JWT operations using lestrrat-go/jwx.
// It generates signing keys, serves local OIDC discovery and JWKS endpoints,
// and signs assertions with caller-selected claims.
//
// It has no dependency on the parent jwt package, allowing that package's tests
// to use the helpers without an import cycle. Keys and assertions are generated
// for tests rather than obtained from a real identity provider.
package jwxtest
