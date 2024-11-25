package credentialhandler_test

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/stretchr/testify/assert"
)

func TestArrayMap_Set(t *testing.T) {
	cases := []struct {
		name     string
		cap      int
		input    [][]string
		expected [][]string
	}{
		{
			name: "set with no overlap",
			cap:  20,
			input: [][]string{
				{"key", "value"},
				{"key2", "value2"},
			},
			expected: [][]string{
				{"key", "value"},
				{"key2", "value2"},
			},
		},
		{
			name: "set with overlap",
			cap:  20,
			input: [][]string{
				{"key", "value"},
				{"key", "value"},
				{"key", "value"},
				{"key2", "value2"},
				{"key2", "value2"},
				{"key2", "value2"},
			},
			expected: [][]string{
				{"key", "value"},
				{"key2", "value2"},
			},
		},
		{
			name: "set preserves insertion order",
			cap:  20,
			input: [][]string{
				{"key2", "value2"},
				{"key", "value"},
				{"key", "value"},
				{"key2", "value2"},
			},
			expected: [][]string{
				{"key2", "value2"},
				{"key", "value"},
			},
		},
		{
			name: "set handles growth from zero",
			cap:  0,
			input: [][]string{
				{"key2", "value2"},
				{"key4", "value4"},
				{"key", "value"},
				{"key3", "value3"},
				{"key7", "value7"},
				{"key5", "value5"},
				{"key8", "value8"},
				{"key0", "value0"},
				{"key9", "value9"},
				{"key6", "value6"},
			},
			expected: [][]string{
				{"key2", "value2"},
				{"key4", "value4"},
				{"key", "value"},
				{"key3", "value3"},
				{"key7", "value7"},
				{"key5", "value5"},
				{"key8", "value8"},
				{"key0", "value0"},
				{"key9", "value9"},
				{"key6", "value6"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := credentialhandler.NewMap(c.cap)
			for _, kv := range c.input {
				m.Set(kv[0], kv[1])
			}

			assert.Equal(t, c.expected, m.Array())
		})
	}
}

func TestArrayMap_LookupGet(t *testing.T) {
	cases := []struct {
		name     string
		input    [][]string
		key      string
		found    bool
		expected string
	}{
		{
			name: "when exists",
			input: [][]string{
				{"key", "value"},
				{"key2", "value2"},
			},
			key:      "key",
			found:    true,
			expected: "value",
		},
		{
			name: "when exists with empty value",
			input: [][]string{
				{"key", ""},
				{"key2", "value2"},
			},
			key:      "key",
			found:    true,
			expected: "",
		},
		{
			name: "when not exists",
			input: [][]string{
				{"key", "value"},
				{"key2", "value2"},
			},
			key:      "key-not-there",
			found:    false,
			expected: "",
		},
	}

	// lookup
	for _, c := range cases {
		t.Run("lookup "+c.name, func(t *testing.T) {
			m := credentialhandler.NewMapFromArray(c.input)

			actual, found := m.Lookup(c.key)

			assert.Equal(t, c.found, found)
			assert.Equal(t, c.expected, actual)
		})
	}

	// get
	for _, c := range cases {
		t.Run("get "+c.name, func(t *testing.T) {
			m := credentialhandler.NewMapFromArray(c.input)

			actual := m.Get(c.key)

			assert.Equal(t, c.expected, actual)
		})
	}
}

func TestArrayMap_Iter(t *testing.T) {
	cases := []struct {
		name     string
		input    [][]string
		expected [][]string
	}{
		{
			name:  "empty set",
			input: [][]string{},
		},
		{
			name: "iterate with insertion order",
			input: [][]string{
				{"key2", "value2"},
				{"key4", "value4"},
				{"key", "value"},
				{"key3", "value3"},
				{"key7", "value7"},
				{"key5", "value5"},
				{"key8", "value8"},
				{"key0", "value0"},
				{"key9", "value9"},
				{"key6", "value6"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := credentialhandler.NewMapFromArray(c.input)

			it := m.Iter()
			curr := 0
			for it.HasNext() {
				k, v := it.Next()
				expectedKV := c.input[curr]

				assert.Equal(t, expectedKV, []string{k, v})

				curr++
			}

			assert.Equal(t, len(c.input), curr)

			assert.PanicsWithError(t, "attempted to iterate past the end of the map", func() {
				it.Next()
			})
		})
	}
}
