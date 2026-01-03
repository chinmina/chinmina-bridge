package github

import (
	"fmt"
	"reflect"
	"strings"
)

// FieldMapper provides a generic way to map JSON field names to struct fields
// and set values on struct instances using reflection. Only string and *string fields are supported.
type FieldMapper[T any] struct {
	fields map[string]reflect.StructField
}

// NewFieldMapper creates a new FieldMapper for type T. It builds a map of JSON
// field names to reflect.StructField for all string and *string fields in T.
func NewFieldMapper[T any]() (*FieldMapper[T], error) {
	var zero T
	t := reflect.TypeOf(zero)

	// Handle pointer types
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("type %s is not a struct", t.Name())
	}

	fields := make(map[string]reflect.StructField)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Only include string and *string fields
		isString := field.Type.Kind() == reflect.String
		isStringPtr := field.Type.Kind() == reflect.Pointer && field.Type.Elem().Kind() == reflect.String
		if !isString && !isStringPtr {
			continue
		}

		// Skip unexported fields (cannot be set via reflection)
		if field.PkgPath != "" {
			continue
		}

		// Get the JSON tag name
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" {
			// If no JSON tag, use the field name
			jsonTag = field.Name
		} else {
			// Handle json tags like "name,omitempty"
			if idx := strings.Index(jsonTag, ","); idx != -1 {
				jsonTag = jsonTag[:idx]
			}
		}

		// Skip fields with json:"-"
		if jsonTag == "-" {
			continue
		}

		fields[jsonTag] = field
	}

	return &FieldMapper[T]{fields: fields}, nil
}

// Has returns true if the field exists in T.
func (fm *FieldMapper[T]) Has(field string) bool {
	_, ok := fm.fields[field]
	return ok
}

// SetAll creates a new instance of T and sets fields based on colon-separated
// field name and value pairs. Each string in fieldValues should be in the format
// "fieldName:value".
func (fm *FieldMapper[T]) SetAll(fieldValues []string) (T, error) {
	var result T
	v := reflect.ValueOf(&result).Elem()

	for _, fv := range fieldValues {
		fieldName, value, ok := strings.Cut(fv, ":")
		if !ok {
			return result, fmt.Errorf("invalid field value format: %q (expected \"field:value\")", fv)
		}

		if err := fm.set(v, fieldName, value); err != nil {
			return result, fmt.Errorf("failed to set field %q: %w", fieldName, err)
		}
	}

	return result, nil
}

// set sets the value of a field on the given reflect.Value.
func (fm *FieldMapper[T]) set(v reflect.Value, fieldName, value string) error {
	field, ok := fm.fields[fieldName]
	if !ok {
		return fmt.Errorf("field %q does not exist", fieldName)
	}

	fieldValue := v.FieldByIndex(field.Index)

	// Handle both string and *string fields
	if field.Type.Kind() == reflect.String {
		fieldValue.SetString(value)
	} else if field.Type.Kind() == reflect.Pointer && field.Type.Elem().Kind() == reflect.String {
		// For *string fields, create a pointer to the value
		ptr := reflect.New(field.Type.Elem())
		ptr.Elem().SetString(value)
		fieldValue.Set(ptr)
	}

	return nil
}
