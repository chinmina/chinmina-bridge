package profile

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWildcardScope(t *testing.T) {
	rs := NewWildcardScope()
	assert.True(t, rs.Wildcard)
	assert.Nil(t, rs.Names)
}

func TestNewSpecificScope(t *testing.T) {
	names := []string{"repo-a", "repo-b"}
	rs := NewSpecificScope(names...)
	assert.False(t, rs.Wildcard)
	assert.Equal(t, names, rs.Names)
}

func TestRepositoryScope_IsWildcard(t *testing.T) {
	tests := []struct {
		name     string
		scope    RepositoryScope
		expected bool
	}{
		{"wildcard scope", NewWildcardScope(), true},
		{"specific scope", NewSpecificScope("repo-a"), false},
		{"zero value", RepositoryScope{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.scope.IsWildcard())
		})
	}
}

func TestRepositoryScope_Contains(t *testing.T) {
	tests := []struct {
		name     string
		scope    RepositoryScope
		repo     string
		expected bool
	}{
		{"wildcard matches any repo", NewWildcardScope(), "any-repo", true},
		{"wildcard matches empty string", NewWildcardScope(), "", true},
		{"specific matches member", NewSpecificScope("repo-a", "repo-b"), "repo-a", true},
		{"specific does not match non-member", NewSpecificScope("repo-a", "repo-b"), "repo-c", false},
		{"empty specific matches nothing", NewSpecificScope(), "repo-a", false},
		{"zero value matches nothing", RepositoryScope{}, "repo-a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.scope.Contains(tt.repo))
		})
	}
}

func TestRepositoryScope_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		scope    RepositoryScope
		expected bool
	}{
		{"zero value", RepositoryScope{}, true},
		{"wildcard scope", NewWildcardScope(), false},
		{"specific scope with names", NewSpecificScope("repo-a"), false},
		{"specific scope with empty names", NewSpecificScope(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.scope.IsZero())
		})
	}
}

func TestRepositoryScope_NamesForDisplay(t *testing.T) {
	tests := []struct {
		name     string
		scope    RepositoryScope
		expected []string
	}{
		{"wildcard returns star", NewWildcardScope(), []string{"*"}},
		{"specific returns names", NewSpecificScope("repo-a", "repo-b"), []string{"repo-a", "repo-b"}},
		{"zero value returns nil", RepositoryScope{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.scope.NamesForDisplay())
		})
	}
}

func TestRepositoryScope_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		scope        RepositoryScope
		expectedJSON string
	}{
		{
			name:         "wildcard",
			scope:        NewWildcardScope(),
			expectedJSON: `{"wildcard":true}`,
		},
		{
			name:         "specific repos",
			scope:        NewSpecificScope("repo-a", "repo-b"),
			expectedJSON: `{"names":["repo-a","repo-b"]}`,
		},
		{
			name:         "zero value",
			scope:        RepositoryScope{},
			expectedJSON: `{}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.scope)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedJSON, string(data))

			var decoded RepositoryScope
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)
			assert.Equal(t, tt.scope, decoded)
		})
	}
}

func TestRepositoryScope_LogValue(t *testing.T) {
	tests := []struct {
		name     string
		scope    RepositoryScope
		expected slog.Value
	}{
		{
			name:     "wildcard logs as star",
			scope:    NewWildcardScope(),
			expected: slog.AnyValue([]string{"*"}),
		},
		{
			name:     "specific logs names",
			scope:    NewSpecificScope("repo-a"),
			expected: slog.AnyValue([]string{"repo-a"}),
		},
		{
			name:     "zero value logs nil",
			scope:    RepositoryScope{},
			expected: slog.AnyValue([]string(nil)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.scope.LogValue())
		})
	}
}
