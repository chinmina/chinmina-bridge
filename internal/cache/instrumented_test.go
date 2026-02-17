package cache

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

// mockCache is a mock implementation of TokenCache for testing.
type mockCache[T any] struct {
	getValue T
	getFound bool
	getError error
	setError error
	invError error
	closeErr error
	getCalls int
	setCalls int
	invCalls int
}

func (m *mockCache[T]) Get(ctx context.Context, key string) (T, bool, error) {
	m.getCalls++
	return m.getValue, m.getFound, m.getError
}

func (m *mockCache[T]) Set(ctx context.Context, key string, token T) error {
	m.setCalls++
	return m.setError
}

func (m *mockCache[T]) Invalidate(ctx context.Context, key string) error {
	m.invCalls++
	return m.invError
}

func (m *mockCache[T]) Close() error {
	return m.closeErr
}

func TestInstrumented_Get_Success(t *testing.T) {
	mock := &mockCache[string]{
		getValue: "test-token",
		getFound: true,
		getError: nil,
	}

	instrumented := NewInstrumented(mock, "test")
	ctx := context.Background()

	value, found, err := instrumented.Get(ctx, "test-key")

	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "test-token", value)
	assert.Equal(t, 1, mock.getCalls)
}

func TestInstrumented_Get_Miss(t *testing.T) {
	mock := &mockCache[string]{
		getValue: "",
		getFound: false,
		getError: nil,
	}

	instrumented := NewInstrumented(mock, "test")
	ctx := context.Background()

	value, found, err := instrumented.Get(ctx, "test-key")

	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, "", value)
	assert.Equal(t, 1, mock.getCalls)
}

func TestInstrumented_Get_Error(t *testing.T) {
	expectedErr := errors.New("cache error")
	mock := &mockCache[string]{
		getValue: "",
		getFound: false,
		getError: expectedErr,
	}

	instrumented := NewInstrumented(mock, "test")
	ctx := context.Background()

	value, found, err := instrumented.Get(ctx, "test-key")

	require.Error(t, err)
	assert.False(t, found)
	assert.Equal(t, "", value)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, 1, mock.getCalls)
}

func TestInstrumented_Set_Success(t *testing.T) {
	mock := &mockCache[string]{
		setError: nil,
	}

	instrumented := NewInstrumented(mock, "test")
	ctx := context.Background()

	err := instrumented.Set(ctx, "test-key", "test-value")

	require.NoError(t, err)
	assert.Equal(t, 1, mock.setCalls)
}

func TestInstrumented_Set_Error(t *testing.T) {
	expectedErr := errors.New("set error")
	mock := &mockCache[string]{
		setError: expectedErr,
	}

	instrumented := NewInstrumented(mock, "test")
	ctx := context.Background()

	err := instrumented.Set(ctx, "test-key", "test-value")

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, 1, mock.setCalls)
}

func TestInstrumented_Invalidate_Success(t *testing.T) {
	mock := &mockCache[string]{
		invError: nil,
	}

	instrumented := NewInstrumented(mock, "test")
	ctx := context.Background()

	err := instrumented.Invalidate(ctx, "test-key")

	require.NoError(t, err)
	assert.Equal(t, 1, mock.invCalls)
}

func TestInstrumented_Invalidate_Error(t *testing.T) {
	expectedErr := errors.New("invalidate error")
	mock := &mockCache[string]{
		invError: expectedErr,
	}

	instrumented := NewInstrumented(mock, "test")
	ctx := context.Background()

	err := instrumented.Invalidate(ctx, "test-key")

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, 1, mock.invCalls)
}

func TestInstrumented_Close(t *testing.T) {
	mock := &mockCache[string]{
		closeErr: nil,
	}

	instrumented := NewInstrumented(mock, "test")

	err := instrumented.Close()

	require.NoError(t, err)
}

func TestInstrumented_Close_Error(t *testing.T) {
	expectedErr := errors.New("close error")
	mock := &mockCache[string]{
		closeErr: expectedErr,
	}

	instrumented := NewInstrumented(mock, "test")

	err := instrumented.Close()

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

func TestInstrumented_CacheType(t *testing.T) {
	tests := []struct {
		name      string
		cacheType string
	}{
		{
			name:      "memory cache type",
			cacheType: "memory",
		},
		{
			name:      "distributed cache type",
			cacheType: "distributed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockCache[string]{}
			instrumented := NewInstrumented(mock, tt.cacheType)

			assert.Equal(t, tt.cacheType, instrumented.cacheType)
		})
	}
}

func TestInstrumented_Get_SpanAttributes(t *testing.T) {
	tests := []struct {
		name     string
		mock     *mockCache[string]
		expected struct {
			status string
		}
	}{
		{
			name: "hit",
			mock: &mockCache[string]{getValue: "token", getFound: true},
			expected: struct{ status string }{
				status: "hit",
			},
		},
		{
			name: "miss",
			mock: &mockCache[string]{getFound: false},
			expected: struct{ status string }{
				status: "miss",
			},
		},
		{
			name: "error",
			mock: &mockCache[string]{getError: errors.New("fail")},
			expected: struct{ status string }{
				status: "error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, getAttrs := tracedContext(t)
			instrumented := NewInstrumented(tt.mock, "test")

			_, _, _ = instrumented.Get(ctx, "key")

			attrs := getAttrs()
			assertCacheSpanAttributes(t, attrs, "get", "test", tt.expected.status)
		})
	}
}

func TestInstrumented_Set_SpanAttributes(t *testing.T) {
	tests := []struct {
		name     string
		mock     *mockCache[string]
		expected struct {
			status string
		}
	}{
		{
			name: "success",
			mock: &mockCache[string]{},
			expected: struct{ status string }{
				status: "success",
			},
		},
		{
			name: "error",
			mock: &mockCache[string]{setError: errors.New("fail")},
			expected: struct{ status string }{
				status: "error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, getAttrs := tracedContext(t)
			instrumented := NewInstrumented(tt.mock, "test")

			_ = instrumented.Set(ctx, "key", "value")

			attrs := getAttrs()
			assertCacheSpanAttributes(t, attrs, "set", "test", tt.expected.status)
		})
	}
}

func TestInstrumented_Invalidate_SpanAttributes(t *testing.T) {
	tests := []struct {
		name     string
		mock     *mockCache[string]
		expected struct {
			status string
		}
	}{
		{
			name: "success",
			mock: &mockCache[string]{},
			expected: struct{ status string }{
				status: "success",
			},
		},
		{
			name: "error",
			mock: &mockCache[string]{invError: errors.New("fail")},
			expected: struct{ status string }{
				status: "error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, getAttrs := tracedContext(t)
			instrumented := NewInstrumented(tt.mock, "test")

			_ = instrumented.Invalidate(ctx, "key")

			attrs := getAttrs()
			assertCacheSpanAttributes(t, attrs, "invalidate", "test", tt.expected.status)
		})
	}
}

func TestInstrumented_NoSpanInContext(t *testing.T) {
	mock := &mockCache[string]{getValue: "token", getFound: true}
	instrumented := NewInstrumented(mock, "test")

	// context.Background() has no span — should not panic
	value, found, err := instrumented.Get(context.Background(), "key")

	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "token", value)
}

func assertCacheSpanAttributes(t *testing.T, attrs []attribute.KeyValue, operation, cacheType, expectedStatus string) {
	t.Helper()

	cacheTypeAttr, ok := spanAttribute(attrs, "cache.type")
	require.True(t, ok, "missing cache.type attribute")
	assert.Equal(t, cacheType, cacheTypeAttr.AsString())

	status, ok := spanAttribute(attrs, "cache."+operation+".status")
	require.True(t, ok, "missing cache.%s.status attribute", operation)
	assert.Equal(t, expectedStatus, status.AsString())

	dur, ok := spanAttribute(attrs, "cache."+operation+".duration")
	require.True(t, ok, "missing cache.%s.duration attribute", operation)
	assert.GreaterOrEqual(t, dur.AsFloat64(), 0.0)
}
