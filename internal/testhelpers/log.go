package testhelpers

import (
	"bytes"
	"log/slog"
	"testing"
)

type testWriter struct {
	t *testing.T
}

func (w *testWriter) Write(p []byte) (n int, err error) {
	w.t.Log(string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}

func SetupLogger(t *testing.T) {
	t.Helper()

	original := slog.Default()
	t.Cleanup(func() {
		slog.SetDefault(original)
	})

	handler := slog.NewTextHandler(&testWriter{t: t}, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
}
