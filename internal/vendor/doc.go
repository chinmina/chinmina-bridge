// Package vendor authorizes resolved profiles and vends scoped GitHub tokens.
// It composes auditing, authorization, caching, repository resolution, and
// minting without owning HTTP request parsing or the live profile store.
//
// Resolved carries a single profile generation, its digest, and app identity
// through the entire request. Authorization runs before cache lookup, and cache
// keys distinguish profile generations and minting installations. Reloads
// therefore cannot combine one generation's authorization with another's scope.
//
// Pipeline repository targets come from Buildkite; organization targets come
// from the compiled profile and any caller-supplied narrowing. An unresolved
// scope fails closed, while an explicit wildcard intentionally reaches all
// repositories in the installation. VendorResult distinguishes a token, a
// successful no-credentials match, and a failure; wire responses are chosen by
// the bridge package rather than by the vendor.
package vendor
