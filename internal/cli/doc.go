// Package cli adapts command-line invocation onto the bridge service. It owns
// parsing, help, and command selection; each command owns its configuration.
// Root construction does not initialize service configuration, logging, or
// telemetry, so help and usage errors work without credentials.
//
// Serve is the default command for launchers that invoke the binary without
// arguments. It rejects positional arguments because the CLI framework routes
// unknown command names to the default command; accepting them could turn a
// typo into an unintended service startup.
//
// Commands return errors rather than reporting them or exiting. The framework's
// exit handler and automatic usage printing are disabled so the process entry
// point reports each error once. ServiceError preserves structured service
// failure reporting; UnhealthyError reports probe failure without a usage hint.
// The bridge package does not depend on the CLI framework.
//
// Healthcheck uses only its flags and their environment sources, not service
// configuration or credentials. Its dedicated HTTP client is uninstrumented,
// bypasses proxies, and rejects redirects so only the target endpoint can
// declare the service healthy.
package cli
