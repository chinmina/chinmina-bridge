package cache

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
