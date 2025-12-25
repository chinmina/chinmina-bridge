package observe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrimMethod(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected string
	}{
		{
			name:     "GET method with path",
			pattern:  "GET /test",
			expected: "/test",
		},
		{
			name:     "POST method with path",
			pattern:  "POST /api/users",
			expected: "/api/users",
		},
		{
			name:     "PUT method with path",
			pattern:  "PUT /resource/{id}",
			expected: "/resource/{id}",
		},
		{
			name:     "DELETE method with path",
			pattern:  "DELETE /items/123",
			expected: "/items/123",
		},
		{
			name:     "PATCH method with path",
			pattern:  "PATCH /update",
			expected: "/update",
		},
		{
			name:     "HEAD method with path",
			pattern:  "HEAD /status",
			expected: "/status",
		},
		{
			name:     "OPTIONS method with path",
			pattern:  "OPTIONS /cors",
			expected: "/cors",
		},
		{
			name:     "CONNECT method with path",
			pattern:  "CONNECT /tunnel",
			expected: "/tunnel",
		},
		{
			name:     "TRACE method with path",
			pattern:  "TRACE /debug",
			expected: "/debug",
		},
		{
			name:     "path without method",
			pattern:  "/api/endpoint",
			expected: "/api/endpoint",
		},
		{
			name:     "path with invalid method prefix",
			pattern:  "INVALID /path",
			expected: "INVALID /path",
		},
		{
			name:     "lowercase method not stripped",
			pattern:  "get /test",
			expected: "get /test",
		},
		{
			name:     "empty string",
			pattern:  "",
			expected: "",
		},
		{
			name:     "method without trailing space",
			pattern:  "GET",
			expected: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimMethod(tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}
