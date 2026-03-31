package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeBasePath(t *testing.T) {
	t.Run("valid paths", func(t *testing.T) {
		cases := []struct {
			name     string
			input    string
			expected string
		}{
			{"empty string", "", ""},
			{"whitespace only", "   ", ""},
			{"root slash", "/", ""},
			{"multiple trailing slashes", "///", ""},
			{"simple path", "/test", "/test"},
			{"without leading slash", "test", "/test"},
			{"trailing slash stripped", "/test/", "/test"},
			{"leading and trailing whitespace", "  /test  ", "/test"},
			{"nested path", "/api/v1/service", "/api/v1/service"},
			{"nested with trailing slash", "/api/v1/", "/api/v1"},
			{"no leading slash nested", "api/v1", "/api/v1"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				result, err := NormalizeBasePath(tc.input)
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			})
		}
	})

	t.Run("invalid paths", func(t *testing.T) {
		cases := []struct {
			name  string
			input string
		}{
			{"double slash in middle", "/test//path"},
			{"double slash at start", "//test"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := NormalizeBasePath(tc.input)
				assert.Error(t, err)
			})
		}
	})
}
