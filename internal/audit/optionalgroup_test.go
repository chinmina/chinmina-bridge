package audit_test

import (
	"log/slog"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptionalGroup_UnmodifiedReturnsZeroAttr(t *testing.T) {
	og := audit.NewOptionalGroup()
	a, hasAttrs := og.Group("key")
	assert.False(t, hasAttrs)
	assert.Equal(t, slog.Attr{}, a, "unmodified group should return zero Attr")
}

func TestOptionalGroup_StrSkipsEmpty(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Str("k", "")
	_, hasAttrs := og.Group("key")
	assert.False(t, hasAttrs, "empty string should not mark modified")
}

func TestOptionalGroup_StrAddsNonEmpty(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Str("k", "v")
	a, hasAttrs := og.Group("g")
	require.True(t, hasAttrs)
	assert.Equal(t, slog.Attr{Key: "g", Value: slog.GroupValue(slog.String("k", "v"))}, a)
}

func TestOptionalGroup_IntSkipsZero(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Int("k", 0)
	_, hasAttrs := og.Group("key")
	assert.False(t, hasAttrs, "zero int should not mark modified")
}

func TestOptionalGroup_IntAddsNonZero(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Int("k", 42)
	a, hasAttrs := og.Group("g")
	require.True(t, hasAttrs)
	assert.Equal(t, slog.Attr{Key: "g", Value: slog.GroupValue(slog.Int("k", 42))}, a)
}

func TestOptionalGroup_BoolAlwaysAdds(t *testing.T) {
	tests := []struct {
		name string
		val  bool
	}{
		{"false", false},
		{"true", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			og := audit.NewOptionalGroup()
			og.Bool("k", tt.val)
			_, hasAttrs := og.Group("g")
			assert.True(t, hasAttrs, "Bool should always mark modified")
		})
	}
}

func TestOptionalGroup_StrsSkipsNilAndEmpty(t *testing.T) {
	tests := []struct {
		name string
		vals []string
	}{
		{"nil", nil},
		{"empty", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			og := audit.NewOptionalGroup()
			og.Strs("k", tt.vals)
			_, hasAttrs := og.Group("key")
			assert.False(t, hasAttrs, "nil/empty slice should not mark modified")
		})
	}
}

func TestOptionalGroup_StrsAddsNonEmpty(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Strs("k", []string{"a", "b"})
	a, hasAttrs := og.Group("g")
	require.True(t, hasAttrs)
	assert.Equal(t, slog.Attr{Key: "g", Value: slog.GroupValue(slog.Any("k", []string{"a", "b"}))}, a)
}

func TestOptionalGroup_AttrAlwaysMarksModified(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Attr(slog.String("k", ""))
	_, hasAttrs := og.Group("g")
	assert.True(t, hasAttrs, "Attr should always mark modified")
}

func TestOptionalGroup_GroupKeyPreserved(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Str("field", "value")
	a, hasAttrs := og.Group("my-group")
	require.True(t, hasAttrs)
	assert.Equal(t, slog.Attr{Key: "my-group", Value: slog.GroupValue(slog.String("field", "value"))}, a)
}
