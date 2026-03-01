package observe

import "log/slog"

const (
	// SlogOTelInfoLevel is the slog level for OTel info events (logr V(1) = zerolog -3).
	SlogOTelInfoLevel = slog.Level(-3)
	// SlogOTelDebugLevel is the slog level for OTel debug events (logr V(4) = zerolog -7).
	SlogOTelDebugLevel = slog.Level(-7)

	// SlogOTelInfoLevelName is the human-readable label for SlogOTelInfoLevel.
	SlogOTelInfoLevelName = "OINF"
	// SlogOTelDebugLevelName is the human-readable label for SlogOTelDebugLevel.
	SlogOTelDebugLevelName = "ODBG"
)
