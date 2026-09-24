package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const runMainEnv = "CHINMINA_BRIDGE_TEST_RUN_MAIN"

// TestMain lets the tests re-execute this binary as the real entry point, so
// exit status and output are observed from a separate process.
func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}

	os.Exit(m.Run())
}

type result struct {
	exitCode int
	stdout   string
	stderr   string
}

// runMain runs the entry point with args and an environment holding no
// service configuration, so a developer's local settings cannot leak in.
func runMain(t *testing.T, args ...string) result {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = []string{
		runMainEnv + "=1",
		// A coverage-instrumented child warns on stderr without somewhere to
		// write its counters.
		"GOCOVERDIR=" + t.TempDir(),
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	require.NoError(t, ctx.Err(), "the process must exit on its own")

	exitCode := 0
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		exitCode = exitErr.ExitCode()
	} else {
		require.NoError(t, err)
	}

	return result{exitCode: exitCode, stdout: stdout.String(), stderr: stderr.String()}
}

func TestEntryPoint_Help(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "root help", args: []string{"--help"}},
		{name: "help command", args: []string{"help"}},
		{name: "serve help", args: []string{"serve", "--help"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runMain(t, tt.args...)

			assert.Equal(t, 0, res.exitCode)
			assert.Contains(t, res.stdout, "USAGE:")
			assert.NotContains(t, res.stdout, "build information", "help must not initialize the service")
			assert.Empty(t, res.stderr)
		})
	}
}

func TestEntryPoint_UsageError(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "unknown command", args: []string{"bogus"}},
		{name: "unknown flag", args: []string{"--bogus"}},
		{name: "extra serve argument", args: []string{"serve", "extra"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runMain(t, tt.args...)

			assert.Equal(t, 1, res.exitCode)
			assert.Empty(t, res.stdout, "a usage error must not initialize the service")
			assert.Contains(t, res.stderr, "chinmina-bridge: ")
			assert.Contains(t, res.stderr, "--help")
		})
	}
}

// Without configuration the service fails at load, which proves the command
// reached the service without needing a working server.
func TestEntryPoint_ServiceFailure(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "default command", args: nil},
		{name: "explicit serve", args: []string{"serve"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runMain(t, tt.args...)

			assert.Equal(t, 1, res.exitCode)
			assert.Contains(t, res.stdout, `"msg":"server failed to start"`)
			assert.Contains(t, res.stdout, "configuration load failed")
			assert.Empty(t, res.stderr, "a service failure is reported once, through the service logger")
		})
	}
}
