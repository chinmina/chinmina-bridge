package main

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/rs/zerolog/log"
)

type AuthServer interface {
	ListenAndServe() error
	Shutdown(ctx context.Context) error
}

func serveHTTP(serverCfg config.ServerConfig, server AuthServer) error {
	serverCtx := context.Background()

	// capture shutdown signals to allow for graceful shutdown
	ctx, stop := signal.NotifyContext(serverCtx,
		syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	// Start the server in a new goroutine
	serverErr := make(chan error, 1)
	go func() {
		log.Info().Int("port", serverCfg.Port).Msg("starting server")
		serverErr <- server.ListenAndServe()
	}()

	var startupError error

	select {
	case err := <-serverErr:
		// Error when starting HTTP server.
		if err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("failed to start server")
		}
		// save this error to return, keep processing shutdown sequence
		startupError = err
	case <-ctx.Done():
		log.Info().Msg("server shutdown requested")
		// Stop receiving signal notifications as soon as possible.
		stop()
	}

	// Gracefully stop the server, allowing a configurable amount of time for
	// in-flight requests to complete
	shutdownTimeout := time.Duration(serverCfg.ShutdownTimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	err := server.Shutdown(ctx)
	if err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	log.Info().Msg("server shutdown complete")

	// if startup failed the error is returned
	return startupError
}
