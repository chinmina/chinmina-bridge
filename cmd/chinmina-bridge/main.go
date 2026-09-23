package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/chinmina/chinmina-bridge/internal/cli"
)

func main() {
	err := cli.Run(context.Background(), os.Args)
	if err == nil {
		return
	}

	if _, ok := errors.AsType[*cli.ServiceError](err); ok {
		// Structured, through the service's configured logger: operators may
		// alert on this record.
		slog.Error("server failed to start", "error", err)
	} else {
		fmt.Fprintf(os.Stderr, "chinmina-bridge: %v\nRun 'chinmina-bridge --help' for usage.\n", err)
	}

	os.Exit(1)
}
