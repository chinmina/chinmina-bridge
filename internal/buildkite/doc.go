// Package buildkite looks up the repository configured for a Buildkite pipeline.
// PipelineLookup is the upstream boundary used by pipeline token vending;
// identity validation belongs to jwt and permission selection to profile.
//
// Each lookup binds its HTTP client to the current request context so outbound
// traces remain attached to the request. Repository URL normalization and
// matching are performed by the vendor package, not by this adapter.
package buildkite
