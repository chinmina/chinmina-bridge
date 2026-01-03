package github

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestStruct struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Value       string
	unexported  string `json:"unexported"`
	IgnoredInt  int    `json:"ignored_int"`
	Skipped     string `json:"-"`
}

type TestStructWithPointers struct {
	Name        *string `json:"name"`
	Description *string `json:"description,omitempty"`
	Value       *string
	unexported  *string `json:"unexported"`
	IgnoredInt  *int    `json:"ignored_int"`
	Skipped     *string `json:"-"`
}

func TestNewFieldMapper(t *testing.T) {
	t.Run("creates field mapper for valid struct", func(t *testing.T) {
		fm, err := NewFieldMapper[TestStruct]()
		require.NoError(t, err)
		assert.NotNil(t, fm)

		// Should have 3 exported string fields: name, description, Value
		assert.True(t, fm.Has("name"))
		assert.True(t, fm.Has("description"))
		assert.True(t, fm.Has("Value"))

		// Should not include unexported field
		assert.False(t, fm.Has("unexported"))

		// Should not include int field
		assert.False(t, fm.Has("ignored_int"))

		// Should not include skipped field
		assert.False(t, fm.Has("Skipped"))
	})

	t.Run("handles non-struct types", func(t *testing.T) {
		_, err := NewFieldMapper[string]()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a struct")
	})
}

func TestFieldMapper_Has(t *testing.T) {
	fm, err := NewFieldMapper[TestStruct]()
	require.NoError(t, err)

	tests := []struct {
		name     string
		field    string
		expected bool
	}{
		{"existing field with json tag", "name", true},
		{"existing field with omitempty", "description", true},
		{"existing field without json tag", "Value", true},
		{"non-existent field", "nonexistent", false},
		{"unexported field", "unexported", false},
		{"int field", "ignored_int", false},
		{"skipped field", "Skipped", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fm.Has(tt.field)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFieldMapper_SetAll(t *testing.T) {
	fm, err := NewFieldMapper[TestStruct]()
	require.NoError(t, err)

	t.Run("sets multiple fields successfully", func(t *testing.T) {
		fieldValues := []string{
			"name:test-name",
			"description:test-description",
			"Value:test-value",
		}

		result, err := fm.SetAll(fieldValues)
		require.NoError(t, err)

		expected := TestStruct{
			Name:        "test-name",
			Description: "test-description",
			Value:       "test-value",
		}
		assert.Equal(t, expected, result)
	})

	t.Run("sets single field", func(t *testing.T) {
		fieldValues := []string{"name:single-value"}

		result, err := fm.SetAll(fieldValues)
		require.NoError(t, err)

		assert.Equal(t, "single-value", result.Name)
		assert.Empty(t, result.Description)
		assert.Empty(t, result.Value)
	})

	t.Run("handles empty slice", func(t *testing.T) {
		result, err := fm.SetAll([]string{})
		require.NoError(t, err)

		assert.Equal(t, TestStruct{}, result)
	})

	t.Run("handles colons in values", func(t *testing.T) {
		fieldValues := []string{"name:value:with:colons"}

		result, err := fm.SetAll(fieldValues)
		require.NoError(t, err)

		assert.Equal(t, "value:with:colons", result.Name)
	})
}

func TestFieldMapper_SetAll_Errors(t *testing.T) {
	fm, err := NewFieldMapper[TestStruct]()
	require.NoError(t, err)

	t.Run("invalid format without colon", func(t *testing.T) {
		fieldValues := []string{"invalid-format"}

		_, err := fm.SetAll(fieldValues)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid field value format")
		assert.Contains(t, err.Error(), "expected \"field:value\"")
	})

	t.Run("non-existent field", func(t *testing.T) {
		fieldValues := []string{"nonexistent:value"}

		_, err := fm.SetAll(fieldValues)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set field")
		assert.Contains(t, err.Error(), "does not exist")
	})
}

func TestFieldMapper_WithPointerFields(t *testing.T) {
	fm, err := NewFieldMapper[TestStructWithPointers]()
	require.NoError(t, err)

	t.Run("sets multiple pointer fields successfully", func(t *testing.T) {
		fieldValues := []string{
			"name:test-name",
			"description:test-description",
			"Value:test-value",
		}

		result, err := fm.SetAll(fieldValues)
		require.NoError(t, err)

		require.NotNil(t, result.Name)
		assert.Equal(t, "test-name", *result.Name)

		require.NotNil(t, result.Description)
		assert.Equal(t, "test-description", *result.Description)

		require.NotNil(t, result.Value)
		assert.Equal(t, "test-value", *result.Value)
	})

	t.Run("filters out non-string pointer fields", func(t *testing.T) {
		// Should not include *int field
		assert.False(t, fm.Has("ignored_int"))

		// Should not include unexported field
		assert.False(t, fm.Has("unexported"))

		// Should not include skipped field
		assert.False(t, fm.Has("Skipped"))
	})
}
