package cache

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type mockStrategy struct {
	encryptResult string
	encryptErr    error
	decryptResult []byte
	decryptErr    error
	storageKey    string
	closeErr      error

	encryptCalls int
	decryptCalls int
}

func (m *mockStrategy) EncryptValue(_ context.Context, token []byte, key string) (string, error) {
	m.encryptCalls++
	return m.encryptResult, m.encryptErr
}

func (m *mockStrategy) DecryptValue(_ context.Context, value string, key string) ([]byte, error) {
	m.decryptCalls++
	return m.decryptResult, m.decryptErr
}

func (m *mockStrategy) StorageKey(key string) string {
	return m.storageKey
}

func (m *mockStrategy) Close() error {
	return m.closeErr
}

func TestInstrumentedStrategy_EncryptValue_Success(t *testing.T) {
	mock := &mockStrategy{
		encryptResult: "encrypted-value",
	}

	instrumented := NewInstrumentedStrategy(mock)

	result, err := instrumented.EncryptValue(t.Context(), []byte("plaintext"), "key")

	require.NoError(t, err)
	assert.Equal(t, "encrypted-value", result)
	assert.Equal(t, 1, mock.encryptCalls)
}

func TestInstrumentedStrategy_EncryptValue_Error(t *testing.T) {
	expectedErr := errors.New("encrypt error")
	mock := &mockStrategy{
		encryptErr: expectedErr,
	}

	instrumented := NewInstrumentedStrategy(mock)

	result, err := instrumented.EncryptValue(t.Context(), []byte("plaintext"), "key")

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, "", result)
	assert.Equal(t, 1, mock.encryptCalls)
}

func TestInstrumentedStrategy_DecryptValue_Success(t *testing.T) {
	mock := &mockStrategy{
		decryptResult: []byte("plaintext"),
	}

	instrumented := NewInstrumentedStrategy(mock)

	result, err := instrumented.DecryptValue(t.Context(), "encrypted-value", "key")

	require.NoError(t, err)
	assert.Equal(t, []byte("plaintext"), result)
	assert.Equal(t, 1, mock.decryptCalls)
}

func TestInstrumentedStrategy_DecryptValue_Error(t *testing.T) {
	expectedErr := errors.New("decrypt error")
	mock := &mockStrategy{
		decryptErr: expectedErr,
	}

	instrumented := NewInstrumentedStrategy(mock)

	result, err := instrumented.DecryptValue(t.Context(), "encrypted-value", "key")

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
	assert.Equal(t, 1, mock.decryptCalls)
}

func TestInstrumentedStrategy_StorageKey(t *testing.T) {
	mock := &mockStrategy{
		storageKey: "enc:my-key",
	}

	instrumented := NewInstrumentedStrategy(mock)

	result := instrumented.StorageKey("my-key")

	assert.Equal(t, "enc:my-key", result)
}

func TestInstrumentedStrategy_Close(t *testing.T) {
	mock := &mockStrategy{}

	instrumented := NewInstrumentedStrategy(mock)

	err := instrumented.Close()

	require.NoError(t, err)
}

func TestInstrumentedStrategy_Close_Error(t *testing.T) {
	expectedErr := errors.New("close error")
	mock := &mockStrategy{
		closeErr: expectedErr,
	}

	instrumented := NewInstrumentedStrategy(mock)

	err := instrumented.Close()

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

// tracedContext creates a context with an active span backed by a SpanRecorder,
// returning the context and a function to retrieve the finished span's attributes.
func tracedContext(t *testing.T) (context.Context, func() []attribute.KeyValue) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	ctx, span := tp.Tracer("test").Start(t.Context(), t.Name())

	return ctx, func() []attribute.KeyValue {
		span.End()
		spans := recorder.Ended()
		require.Len(t, spans, 1, "expected exactly one recorded span")
		return spans[0].Attributes()
	}
}

func spanAttribute(attrs []attribute.KeyValue, key string) (attribute.Value, bool) {
	for _, a := range attrs {
		if string(a.Key) == key {
			return a.Value, true
		}
	}
	return attribute.Value{}, false
}

func TestInstrumentedStrategy_EncryptValue_SpanAttributes(t *testing.T) {
	tests := []struct {
		name            string
		mock            *mockStrategy
		expectedOutcome string
	}{
		{
			name:            "success",
			mock:            &mockStrategy{encryptResult: "encrypted"},
			expectedOutcome: "success",
		},
		{
			name:            "error",
			mock:            &mockStrategy{encryptErr: errors.New("encrypt failed")},
			expectedOutcome: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, getAttrs := tracedContext(t)
			instrumented := NewInstrumentedStrategy(tt.mock)

			_, _ = instrumented.EncryptValue(ctx, []byte("plaintext"), "key")

			attrs := getAttrs()

			dur, ok := spanAttribute(attrs, "cache.encrypt.duration")
			require.True(t, ok, "missing cache.encrypt.duration attribute")
			assert.GreaterOrEqual(t, dur.AsFloat64(), 0.0)

			outcome, ok := spanAttribute(attrs, "cache.encrypt.outcome")
			require.True(t, ok, "missing cache.encrypt.outcome attribute")
			assert.Equal(t, tt.expectedOutcome, outcome.AsString())
		})
	}
}

func TestInstrumentedStrategy_DecryptValue_SpanAttributes(t *testing.T) {
	tests := []struct {
		name            string
		mock            *mockStrategy
		expectedOutcome string
	}{
		{
			name:            "success",
			mock:            &mockStrategy{decryptResult: []byte("plaintext")},
			expectedOutcome: "success",
		},
		{
			name:            "error",
			mock:            &mockStrategy{decryptErr: errors.New("decrypt failed")},
			expectedOutcome: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, getAttrs := tracedContext(t)
			instrumented := NewInstrumentedStrategy(tt.mock)

			_, _ = instrumented.DecryptValue(ctx, "encrypted-value", "key")

			attrs := getAttrs()

			dur, ok := spanAttribute(attrs, "cache.decrypt.duration")
			require.True(t, ok, "missing cache.decrypt.duration attribute")
			assert.GreaterOrEqual(t, dur.AsFloat64(), 0.0)

			outcome, ok := spanAttribute(attrs, "cache.decrypt.outcome")
			require.True(t, ok, "missing cache.decrypt.outcome attribute")
			assert.Equal(t, tt.expectedOutcome, outcome.AsString())
		})
	}
}

func TestInstrumentedStrategy_NoSpanInContext(t *testing.T) {
	// Verifies no panic when context has no active span (uses the no-op span).
	mock := &mockStrategy{encryptResult: "encrypted"}
	instrumented := NewInstrumentedStrategy(mock)

	result, err := instrumented.EncryptValue(t.Context(), []byte("plaintext"), "key")

	require.NoError(t, err)
	assert.Equal(t, "encrypted", result)
}
