package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/chinmina/chinmina-bridge/internal/bridge"
)

func main() {
	err := bridge.Run(context.Background())
	if err != nil {
		slog.Error("server failed to start", "error", err)
		os.Exit(1)
	}
}
