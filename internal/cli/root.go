// Package cli adapts command-line invocation onto the bridge service. It owns
// parsing, help, and command selection; the commands it dispatches to own
// their configuration.
package cli

import (
	"context"
	"io"
	"os"

	"github.com/chinmina/chinmina-bridge/internal/bridge"
	urfave "github.com/urfave/cli/v3"
)

// Options holds the dependencies of the command tree, so tests can observe
// dispatch without starting a server.
type Options struct {
	// Serve runs the bridge service until it shuts down.
	Serve func(context.Context) error

	Writer    io.Writer
	ErrWriter io.Writer
}

// New builds the root command. Nothing here may load configuration or
// configure logging: help and usage errors must work without credentials.
func New(opts Options) *urfave.Command {
	return &urfave.Command{
		Name:  "chinmina-bridge",
		Usage: "vend short-lived GitHub tokens to Buildkite pipelines",

		// Existing launchers, including the published image whose ko-built
		// entrypoint cannot carry arguments, run the binary bare.
		DefaultCommand: serveCommandName,

		Writer:    opts.Writer,
		ErrWriter: opts.ErrWriter,

		// The entry point owns reporting and exit. The library's default
		// handler calls os.Exit for an ExitCoder, which would skip the entry
		// point and end a test process.
		ExitErrHandler: func(context.Context, *urfave.Command, error) {},
		OnUsageError:   returnUsageError,

		Commands: []*urfave.Command{
			serveCommand(opts.Serve),
		},
	}
}

// Run executes the command selected by args against the real service.
func Run(ctx context.Context, args []string) error {
	return New(Options{
		Serve:     bridge.Run,
		Writer:    os.Stdout,
		ErrWriter: os.Stderr,
	}).Run(ctx, args)
}

// returnUsageError leaves reporting to the entry point. Every command sets it:
// without it, the library prints its own report and help, so the error would
// be reported twice.
func returnUsageError(_ context.Context, _ *urfave.Command, err error, _ bool) error {
	return err
}
