package cli_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"
)

// dispatch runs the command with a serve seam that records calls, so the
// tests observe command selection without starting a server.
type dispatch struct {
	serveCalls int
	serveErr   error
	stdout     bytes.Buffer
	stderr     bytes.Buffer
}

func (d *dispatch) run(t *testing.T, args ...string) error {
	t.Helper()

	cmd := cli.New(cli.Options{
		Serve: func(context.Context) error {
			d.serveCalls++
			return d.serveErr
		},
		Writer:    &d.stdout,
		ErrWriter: &d.stderr,
	})

	return cmd.Run(t.Context(), append([]string{"chinmina-bridge"}, args...))
}

func TestDispatch_Serve(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no arguments serves by default", args: nil},
		{name: "explicit serve", args: []string{"serve"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &dispatch{}

			err := d.run(t, tt.args...)

			require.NoError(t, err)
			assert.Equal(t, 1, d.serveCalls)
		})
	}
}

func TestDispatch_Help(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{name: "root long flag", args: []string{"--help"}, expected: "serve"},
		{name: "root short flag", args: []string{"-h"}, expected: "serve"},
		{name: "help command", args: []string{"help"}, expected: "serve"},
		{name: "serve flag", args: []string{"serve", "--help"}, expected: "chinmina-bridge serve"},
		{name: "help for serve", args: []string{"help", "serve"}, expected: "chinmina-bridge serve"},
		{name: "root lists healthcheck", args: []string{"--help"}, expected: "healthcheck"},
		{name: "healthcheck flag", args: []string{"healthcheck", "--help"}, expected: "chinmina-bridge healthcheck"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &dispatch{}

			err := d.run(t, tt.args...)

			require.NoError(t, err)
			assert.Equal(t, 0, d.serveCalls, "help must not start the service")
			assert.Contains(t, d.stdout.String(), tt.expected)
		})
	}
}

// With a default command, the library hands an unrecognised command name or
// flag to serve as a positional argument rather than rejecting it. These
// cases prove a typo cannot start the service.
func TestDispatch_InvalidArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "unknown command", args: []string{"bogus"}},
		{name: "unknown root flag", args: []string{"--bogus"}},
		{name: "unknown root short flag", args: []string{"-z"}},
		{name: "extra serve argument", args: []string{"serve", "extra"}},
		{name: "unknown serve flag", args: []string{"serve", "--bogus"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &dispatch{}

			err := d.run(t, tt.args...)

			require.Error(t, err)
			assert.Equal(t, 0, d.serveCalls, "invalid arguments must not start the service")

			_, isServiceErr := errors.AsType[*cli.ServiceError](err)
			assert.False(t, isServiceErr, "a usage error must not be reported as a service failure")

			assert.Empty(t, d.stdout.String(), "the entry point reports the error once")
			assert.Empty(t, d.stderr.String(), "the entry point reports the error once")
		})
	}
}

func TestDispatch_ServeErrorIsReturned(t *testing.T) {
	d := &dispatch{serveErr: errors.New("startup failed")}

	err := d.run(t)

	require.Error(t, err)
	assert.ErrorIs(t, err, d.serveErr)
	assert.EqualError(t, err, "startup failed", "the entry point logs the service's message undecorated")
	assert.Equal(t, 1, d.serveCalls)

	_, isServiceErr := errors.AsType[*cli.ServiceError](err)
	assert.True(t, isServiceErr, "a service failure is reported as one")
}

// The library's default error handler calls os.Exit for an ExitCoder. Were it
// active, this test process would end here instead of failing an assertion,
// and a real process would skip the entry point's reporting.
func TestDispatch_ExitCoderDoesNotExitProcess(t *testing.T) {
	d := &dispatch{serveErr: urfave.Exit("exit requested", 3)}

	err := d.run(t)

	require.Error(t, err)
	assert.ErrorIs(t, err, d.serveErr)
}

// Run binds the real service, so this proves the production wiring answers
// help without loading configuration: the test environment holds none.
func TestRun_HelpDoesNotStartTheService(t *testing.T) {
	err := cli.Run(t.Context(), []string{"chinmina-bridge", "--help"})

	require.NoError(t, err)
}
