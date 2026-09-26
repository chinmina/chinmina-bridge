// Package github provides GitHub App clients, installation-token minting, and
// repository content access. It supports local private keys and KMS-backed
// signing; client construction uses the long-lived server context so signing
// remains usable after startup completes.
//
// Registry resolves profile-selected app names to credential-free AppIdentity
// values. Registry verification checks installation ownership when additional
// apps are configured; unavailable apps cannot be resolved by request handlers.
// Clients and signing credentials stay inside this boundary rather than
// travelling through profiles, cache keys, or request audit state.
//
// Profile authorization and repository scope selection belong to the profile
// and vendor packages. This package translates the resulting scope and
// permissions into GitHub API requests.
package github
