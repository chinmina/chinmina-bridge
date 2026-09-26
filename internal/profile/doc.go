// Package profile retrieves, compiles, and matches token authorization profiles.
// It turns profile YAML into typed pipeline and organization attributes with
// claim matchers, repository scopes, app names, and a configuration digest.
// Unavailable profiles retain their validation errors separately from profiles
// that are not defined, allowing callers to distinguish those failure modes.
//
// Compiled Profiles values are immutable; ProfileStore replaces a generation
// as a unit. Request lookups return the profile and digest under the same lock
// so callers can carry a consistent snapshot through authorization and vending.
// Attribute slices are treated as immutable after construction.
//
// RefreshTask retrieves configuration in the background and signals its first
// successful load. The bridge owns the startup readiness gate; this package
// owns profile retrieval and compilation, not token minting or HTTP responses.
package profile
