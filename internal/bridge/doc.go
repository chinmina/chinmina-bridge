// Package bridge constructs and runs the token-vending HTTP service.
// Run owns configuration, telemetry, upstream clients, profile refresh, and
// shutdown. It is independent of command-line parsing and does not exit the
// process; cmd/chinmina-bridge owns final error reporting and exit status.
//
// Startup validates local configuration before network access and installs the
// outbound transport before constructing clients. When a profile source is
// configured, the service waits for its first successful load before listening.
// Registered shutdown hooks run on startup failures as well as normal shutdown.
//
// Routes apply request limits, auditing, and JWT validation before vending.
// Handlers resolve a profile generation and app identity once, then pass that
// value through authorization, caching, and minting. JSON and Git credential
// responses share the vending result but retain their own wire formats.
// A credential context with no applicable credentials is a successful empty
// response, allowing Git to continue to another helper.
package bridge
