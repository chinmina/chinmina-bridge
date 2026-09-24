package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"
)

const serveCommandName = "serve"

// ServiceError marks a failure of the running service, as distinct from a
// usage error, so the entry point can report each in its expected form.
type ServiceError struct {
	Err error
}

func (e *ServiceError) Error() string { return e.Err.Error() }

func (e *ServiceError) Unwrap() error { return e.Err }

func serveCommand(serve func(context.Context) error) *urfave.Command {
	return &urfave.Command{
		Name:  serveCommandName,
		Usage: "run the token vending HTTP service (default command)",
		Description: "Configuration is read from the environment. See " +
			"https://chinmina.github.io/reference/configuration/",
		ArgValidator: noArguments,
		OnUsageError: returnUsageError,
		Action: func(ctx context.Context, _ *urfave.Command) error {
			err := serve(ctx)
			if err != nil {
				return &ServiceError{Err: err}
			}

			return nil
		},
	}
}

// noArguments stops a mistyped command from starting the service. Because
// serve is the default command, the library routes an unrecognised command
// name here as a positional argument instead of rejecting it.
func noArguments(_ context.Context, cmd *urfave.Command) error {
	if cmd.Args().Present() {
		return fmt.Errorf("unexpected argument %q", cmd.Args().First())
	}

	return nil
}
