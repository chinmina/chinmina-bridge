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
	a := og.Group("key")
	assert.Equal(t, slog.Attr{}, a, "unmodified group should return zero Attr")
}

func TestOptionalGroup_StrSkipsEmpty(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Str("k", "")
	assert.Equal(t, slog.Attr{}, og.Group("key"), "empty string should not mark modified")
}

func TestOptionalGroup_StrAddsNonEmpty(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Str("k", "v")
	a := og.Group("g")
	require.NotEqual(t, slog.Attr{}, a)
	assert.Equal(t, "g", a.Key)
}

func TestOptionalGroup_IntSkipsZero(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Int("k", 0)
	assert.Equal(t, slog.Attr{}, og.Group("key"), "zero int should not mark modified")
}

func TestOptionalGroup_IntAddsNonZero(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Int("k", 42)
	a := og.Group("g")
	require.NotEqual(t, slog.Attr{}, a)
	assert.Equal(t, "g", a.Key)
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
			a := og.Group("g")
			assert.NotEqual(t, slog.Attr{}, a, "Bool should always mark modified")
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
			assert.Equal(t, slog.Attr{}, og.Group("key"), "nil/empty slice should not mark modified")
		})
	}
}

func TestOptionalGroup_StrsAddsNonEmpty(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Strs("k", []string{"a", "b"})
	a := og.Group("g")
	require.NotEqual(t, slog.Attr{}, a)
	assert.Equal(t, "g", a.Key)
}

func TestOptionalGroup_AttrAlwaysMarksModified(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Attr(slog.String("k", ""))
	a := og.Group("g")
	assert.NotEqual(t, slog.Attr{}, a, "Attr should always mark modified")
}

func TestOptionalGroup_GroupKeyPreserved(t *testing.T) {
	og := audit.NewOptionalGroup()
	og.Str("field", "value")
	a := og.Group("my-group")
	assert.Equal(t, "my-group", a.Key)
}
