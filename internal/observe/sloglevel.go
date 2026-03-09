package observe

import "log/slog"

const (
	// SlogOTelInfoLevel is the slog level for OTel info events (logr V(4) via logr.FromSlogHandler).
	SlogOTelInfoLevel = slog.Level(-4)
	// SlogOTelDebugLevel is the slog level for OTel debug events (logr V(8) via logr.FromSlogHandler).
	SlogOTelDebugLevel = slog.Level(-8)
)
