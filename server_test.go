package main

import (
	"context"
	"errors"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockServer struct {
	mock.Mock
}

func (m *MockServer) ListenAndServe() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockServer) Shutdown(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockServer) RegisterOnShutdown(f func()) {
	m.Called(f)
}

func TestServeHTTP_StartupError(t *testing.T) {
	// deregister signal handlers afterwards just in case they're left around
	defer signal.Reset()

	expectedErr := errors.New("startup error")

	mockServer := MockServer{}
	mockServer.On("ListenAndServe").Return(expectedErr)
	mockServer.On("Shutdown", mock.Anything).Return(nil)

	serverCfg := config.ServerConfig{Port: -1, ShutdownTimeoutSeconds: 25}
	err := serveHTTP(serverCfg, &mockServer)

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockServer.AssertExpectations(t)
}

func TestServeHTTP_ShutdownSignal(t *testing.T) {
	// deregister signal handlers afterwards just in case they're left around
	defer signal.Reset()

	// set up the server to run for a period of time if an expected signal
	// interrupt isn't received
	expectedErr := errors.New("startup should be interrupted before this error is returned")
	mockServer := MockServer{}
	mockServer.On("ListenAndServe").Return(expectedErr).WaitUntil(time.After(5 * time.Second))
	mockServer.On("Shutdown", mock.Anything).Return(nil)

	// send termination signal after the mock server has had enough time to start
	startupTimer, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go func() {
		<-startupTimer.Done()
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	}()

	serverCfg := config.ServerConfig{Port: -1, ShutdownTimeoutSeconds: 25}
	err := serveHTTP(serverCfg, &mockServer)

	require.NoError(t, err)

	mockServer.AssertExpectations(t)
}

func TestServeHTTP_GracefulShutdown(t *testing.T) {
	// deregister signal handlers afterwards just in case they're left around
	defer signal.Reset()

	var actualError error

	mockServer := MockServer{}
	mockServer.On("ListenAndServe").Return(nil)
	mockServer.On("Shutdown", mock.Anything).Run(func(args mock.Arguments) {
		ctx := args.Get(0).(context.Context)
		<-ctx.Done()
		actualError = ctx.Err()
	}).Return(errors.New("ignore this"))

	serverCfg := config.ServerConfig{Port: -1, ShutdownTimeoutSeconds: 1}
	_ = serveHTTP(serverCfg, &mockServer)

	require.Error(t, actualError)
	assert.ErrorContains(t, actualError, "context deadline exceeded")

	mockServer.AssertExpectations(t)
}
