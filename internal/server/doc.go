// Package server coordinates shutdown hooks shared by service lifecycle paths.
// ShutdownHooks executes registered cleanup in registration order, continuing
// after errors. Concurrent Execute calls wait for the same execution to finish
// rather than running cleanup again.
//
// Hooks are registered during startup before execution can begin. The lock
// guards execution ownership only; callbacks run outside it. The bridge package
// owns HTTP serving and calls these hooks on startup failure and shutdown.
package server
