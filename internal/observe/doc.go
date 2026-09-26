// Package observe configures OpenTelemetry and continuous profiling for the
// service. It supplies instrumented HTTP routing and outbound transports as
// well as trace, metric, and profiling lifecycle setup.
//
// Configure installs process-wide telemetry providers and returns a shutdown
// function that flushes pending data. The bridge owns registering cleanup and
// installing the outbound transport before upstream clients are constructed.
// Routes registered directly on the underlying HTTP mux can bypass telemetry,
// as the service health endpoint does.
package observe
