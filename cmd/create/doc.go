// Command create builds locally signed Buildkite-style JWTs for development.
// It is built as oidc-local and used by the local credential helper to exercise
// a local bridge without obtaining assertions from Buildkite.
//
// The command reads UTIL_* settings and a development signing key relative to
// the repository root, then writes the signed assertion to standard output.
// It is a local testing utility, not a production identity provider.
package main
