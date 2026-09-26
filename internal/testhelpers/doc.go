// Package testhelpers supplies shared test infrastructure for upstream adapters
// and service integration tests. It includes configurable GitHub and Buildkite
// HTTP servers and log-capture helpers; the bridge's API harness composes these
// with real handlers and authentication middleware.
//
// Integration-tagged helpers also provision disposable Valkey containers and
// test encryption keysets. Those helpers require Docker, register cleanup with
// the test, and avoid relying on a separately running service stack.
package testhelpers
