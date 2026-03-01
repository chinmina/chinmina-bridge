package loginfra_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/loginfra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testLevel = slog.Level(42)

func logLevelStr(t *testing.T, replaceAttr func([]string, slog.Attr) slog.Attr, level slog.Level) string {
	t.Helper()
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level:       slog.Level(-100),
		ReplaceAttr: replaceAttr,
	})
	slog.New(handler).Log(context.Background(), level, "msg")
	var result map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	return result["level"].(string)
}

func TestReplaceLevel_MappedLevelProducesLabel(t *testing.T) {
	replace := loginfra.ReplaceLevel(map[slog.Level]string{
		testLevel: "custom",
	})
	assert.Equal(t, "custom", logLevelStr(t, replace, testLevel))
}

func TestReplaceLevel_StandardLevelsPassThrough(t *testing.T) {
	replace := loginfra.ReplaceLevel(map[slog.Level]string{
		testLevel: "custom",
	})

	tests := []struct {
		name     string
		level    slog.Level
		expected string
	}{
		{"debug", slog.LevelDebug, "DEBUG"},
		{"info", slog.LevelInfo, "INFO"},
		{"warn", slog.LevelWarn, "WARN"},
		{"error", slog.LevelError, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, logLevelStr(t, replace, tt.level))
		})
	}
}

func TestReplaceLevel_NonLevelAttrPassesThrough(t *testing.T) {
	replace := loginfra.ReplaceLevel(map[slog.Level]string{testLevel: "custom"})

	// msg attr has key "msg", not "level" — should pass through unchanged
	msg := replace(nil, slog.String("msg", "hello"))
	assert.Equal(t, slog.String("msg", "hello"), msg)
}

func TestReplaceLevel_AttrsInsideGroupPassThrough(t *testing.T) {
	replace := loginfra.ReplaceLevel(map[slog.Level]string{testLevel: "custom"})

	// level key inside a group should not be rewritten
	a := slog.String(slog.LevelKey, "something")
	result := replace([]string{"group"}, a)
	assert.Equal(t, a, result)
}

func TestReplaceLevel_EmptyMapPassesAllThrough(t *testing.T) {
	replace := loginfra.ReplaceLevel(map[slog.Level]string{})

	tests := []struct {
		level    slog.Level
		expected string
	}{
		{slog.LevelDebug, "DEBUG"},
		{slog.LevelInfo, "INFO"},
		{testLevel, testLevel.String()}, // slog default representation for unknown level
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, logLevelStr(t, replace, tt.level))
	}
}

func TestReplaceLevel_NilValuePassesThrough(t *testing.T) {
	replace := loginfra.ReplaceLevel(map[slog.Level]string{testLevel: "custom"})

	// Attr with LevelKey but non-Level value (e.g. a string)
	a := slog.String(slog.LevelKey, "notAlevel")
	result := replace(nil, a)
	assert.Equal(t, a, result)
}

func TestReplaceLevel_MultipleMappings(t *testing.T) {
	const levelA = slog.Level(20)
	const levelB = slog.Level(-3)
	const levelC = slog.Level(-7)

	replace := loginfra.ReplaceLevel(map[slog.Level]string{
		levelA: "audit",
		levelB: "OINF",
		levelC: "ODBG",
	})

	assert.Equal(t, "audit", logLevelStr(t, replace, levelA))
	assert.Equal(t, "OINF", logLevelStr(t, replace, levelB))
	assert.Equal(t, "ODBG", logLevelStr(t, replace, levelC))
}
