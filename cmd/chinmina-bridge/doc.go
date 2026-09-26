// Command chinmina-bridge dispatches service and health-probe invocations through
// internal/cli. This process boundary owns final error reporting and exit status;
// command parsing and service startup remain in their respective packages.
//
// Service failures use structured logging, unhealthy probes report a diagnostic
// without a usage hint, and other command errors point the caller to help.
package main
