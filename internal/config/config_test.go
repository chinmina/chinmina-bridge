package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sethvargo/go-envconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requiredConfig returns a map with all required configuration values
var requiredConfig = map[string]string{
	"JWT_BUILDKITE_ORGANIZATION_SLUG": "test-org",
	"BUILDKITE_API_TOKEN":             "test-token",
	"GITHUB_APP_ID":                   "123",
	"GITHUB_APP_INSTALLATION_ID":      "456",
	"GITHUB_APP_PRIVATE_KEY":          "test-key",
}

func TestCacheConfig_Defaults(t *testing.T) {
	lookuper := envconfig.MapLookuper(requiredConfig)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)
	assert.Equal(t, "memory", cfg.Cache.Type)
}

func TestValkeyConfig(t *testing.T) {
	configMap := map[string]string{
		"CACHE_TYPE":      "valkey",
		"VALKEY_ADDRESS":  "localhost:6379",
		"VALKEY_USERNAME": "testuser",
		"VALKEY_PASSWORD": "testpass",
	}
	lookuper := envconfig.MultiLookuper(
		envconfig.MapLookuper(requiredConfig),
		envconfig.MapLookuper(configMap),
	)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)

	assert.Equal(t, "valkey", cfg.Cache.Type)
	expected := ValkeyConfig{
		Address:  "localhost:6379",
		Username: "testuser",
		Password: "testpass",
		TLS:      true, // default
	}
	assert.Equal(t, expected, cfg.Cache.Valkey)
}

func TestValkeyConfig_IAM(t *testing.T) {
	configMap := map[string]string{
		"CACHE_TYPE":            "valkey",
		"VALKEY_ADDRESS":        "master.my-cluster.abc123.use1.cache.amazonaws.com:6379",
		"VALKEY_IAM_ENABLED":    "true",
		"VALKEY_USERNAME":       "iam-user",
		"VALKEY_IAM_CACHE_NAME": "my-cluster",
	}
	lookuper := envconfig.MultiLookuper(
		envconfig.MapLookuper(requiredConfig),
		envconfig.MapLookuper(configMap),
	)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)

	expected := ValkeyConfig{
		Address:      "master.my-cluster.abc123.use1.cache.amazonaws.com:6379",
		TLS:          true, // forced on by IAM validation
		IAMEnabled:   true,
		Username:     "iam-user",
		IAMCacheName: "my-cluster",
	}
	assert.Equal(t, expected, cfg.Cache.Valkey)
}

func TestValkeyConfig_IAM_ForcesTLS(t *testing.T) {
	configMap := map[string]string{
		"CACHE_TYPE":            "valkey",
		"VALKEY_ADDRESS":        "localhost:6379",
		"VALKEY_TLS":            "false",
		"VALKEY_IAM_ENABLED":    "true",
		"VALKEY_USERNAME":       "iam-user",
		"VALKEY_IAM_CACHE_NAME": "my-cluster",
	}
	lookuper := envconfig.MultiLookuper(
		envconfig.MapLookuper(requiredConfig),
		envconfig.MapLookuper(configMap),
	)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)
	assert.True(t, cfg.Cache.Valkey.TLS, "IAM auth should force TLS on")
}

func TestValkeyConfig_TLSTrue(t *testing.T) {
	configMap := map[string]string{
		"VALKEY_ADDRESS": "localhost:6379",
		"VALKEY_TLS":     "true",
	}
	lookuper := envconfig.MultiLookuper(
		envconfig.MapLookuper(requiredConfig),
		envconfig.MapLookuper(configMap),
	)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)

	expected := ValkeyConfig{
		Address: "localhost:6379",
		TLS:     true,
	}
	assert.Equal(t, expected, cfg.Cache.Valkey)
}

func TestValkeyConfig_TLSFalse(t *testing.T) {
	configMap := map[string]string{
		"VALKEY_ADDRESS": "localhost:6379",
		"VALKEY_TLS":     "false",
	}
	lookuper := envconfig.MultiLookuper(
		envconfig.MapLookuper(requiredConfig),
		envconfig.MapLookuper(configMap),
	)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)

	expected := ValkeyConfig{
		Address: "localhost:6379",
		TLS:     false,
	}
	assert.Equal(t, expected, cfg.Cache.Valkey)
}

func TestCacheConfig_Validate_Success(t *testing.T) {
	tests := []struct {
		name   string
		config CacheConfig
	}{
		{
			name: "memory cache",
			config: CacheConfig{
				Type: "memory",
			},
		},
		{
			name: "valkey without encryption",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
			},
		},
		{
			name: "valkey with AWS encryption",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled:           true,
					KeysetURI:         "aws-secretsmanager://my-keyset",
					KMSEnvelopeKeyURI: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/abc",
				},
			},
		},
		{
			name: "valkey with file encryption",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled:    true,
					KeysetFile: "/path/to/keyset.json",
				},
			},
		},
		{
			name: "IAM enabled",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address:      "localhost:6379",
					IAMEnabled:   true,
					Username:     "iam-user",
					IAMCacheName: "my-cluster",
				},
			},
		},
		{
			name: "IAM enabled with serverless",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address:       "localhost:6379",
					IAMEnabled:    true,
					Username:      "iam-user",
					IAMCacheName:  "my-serverless-cache",
					IAMServerless: true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestCacheConfig_Validate_Failures(t *testing.T) {
	tests := []struct {
		name        string
		config      CacheConfig
		expectedErr string
	}{
		{
			name: "encryption requires valkey",
			config: CacheConfig{
				Type: "memory",
				Encryption: CacheEncryptionConfig{
					Enabled:           true,
					KeysetURI:         "aws-secretsmanager://my-keyset",
					KMSEnvelopeKeyURI: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/abc",
				},
			},
			expectedErr: "cache encryption requires CACHE_TYPE=valkey",
		},
		{
			name: "AWS encryption requires keyset URI when KMS URI set",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled:           true,
					KMSEnvelopeKeyURI: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/abc",
				},
			},
			expectedErr: "CACHE_ENCRYPTION_KEYSET_URI required when CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI is set",
		},
		{
			name: "AWS encryption requires KMS URI when keyset URI set",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled:   true,
					KeysetURI: "aws-secretsmanager://my-keyset",
				},
			},
			expectedErr: "CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI required when CACHE_ENCRYPTION_KEYSET_URI is set",
		},
		{
			name: "encryption enabled with no keyset source",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled: true,
				},
			},
			expectedErr: "encryption enabled but no keyset source configured",
		},
		{
			name: "file and AWS keyset are mutually exclusive",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled:           true,
					KeysetFile:        "/path/to/keyset.json",
					KeysetURI:         "aws-secretsmanager://my-keyset",
					KMSEnvelopeKeyURI: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/abc",
				},
			},
			expectedErr: "CACHE_ENCRYPTION_KEYSET_FILE is mutually exclusive",
		},
		{
			name: "file and partial AWS config are mutually exclusive",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled:    true,
					KeysetFile: "/path/to/keyset.json",
					KeysetURI:  "aws-secretsmanager://my-keyset",
				},
			},
			expectedErr: "CACHE_ENCRYPTION_KEYSET_FILE is mutually exclusive",
		},
		{
			name: "valkey requires address",
			config: CacheConfig{
				Type: "valkey",
			},
			expectedErr: "VALKEY_ADDRESS required when CACHE_TYPE=valkey",
		},
		{
			name: "IAM missing username",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address:      "localhost:6379",
					IAMEnabled:   true,
					IAMCacheName: "my-cluster",
				},
			},
			expectedErr: "VALKEY_USERNAME required as IAM user ID",
		},
		{
			name: "IAM missing cache name",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address:    "localhost:6379",
					IAMEnabled: true,
					Username:   "iam-user",
				},
			},
			expectedErr: "VALKEY_IAM_CACHE_NAME required",
		},
		{
			name: "IAM with password set",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address:      "localhost:6379",
					IAMEnabled:   true,
					Username:     "iam-user",
					IAMCacheName: "my-cluster",
					Password:     "static-pass",
				},
			},
			expectedErr: "VALKEY_PASSWORD must be empty when IAM authentication is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestObserveConfig_Validate(t *testing.T) {
	t.Run("pyroscope enabled requires address", func(t *testing.T) {
		cfg := ObserveConfig{
			PyroscopeEnabled:       true,
			PyroscopeServerAddress: "",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OBSERVE_PYROSCOPE_SERVER_ADDRESS")
	})

	t.Run("pyroscope disabled skips address check", func(t *testing.T) {
		cfg := ObserveConfig{
			PyroscopeEnabled:       false,
			PyroscopeServerAddress: "",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("pyroscope enabled with address is valid", func(t *testing.T) {
		cfg := ObserveConfig{
			PyroscopeEnabled:       true,
			PyroscopeServerAddress: "http://pyroscope:4040",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestLoad_Errors(t *testing.T) {
	tests := []struct {
		name        string
		configMap   map[string]string
		expectedErr string
	}{
		{
			name: "missing required env var",
			configMap: map[string]string{
				"JWT_BUILDKITE_ORGANIZATION_SLUG": "test-org",
				// BUILDKITE_API_TOKEN is missing
				"GITHUB_APP_ID":              "123",
				"GITHUB_APP_INSTALLATION_ID": "456",
				"GITHUB_APP_PRIVATE_KEY":     "test-key",
			},
			expectedErr: "BUILDKITE_API_TOKEN",
		},
		{
			name: "invalid cache configuration",
			configMap: map[string]string{
				"JWT_BUILDKITE_ORGANIZATION_SLUG": "test-org",
				"BUILDKITE_API_TOKEN":             "test-token",
				"GITHUB_APP_ID":                   "123",
				"GITHUB_APP_INSTALLATION_ID":      "456",
				"GITHUB_APP_PRIVATE_KEY":          "test-key",
				// Enable valkey without address
				"CACHE_TYPE": "valkey",
			},
			expectedErr: "invalid cache configuration",
		},
		{
			name: "pyroscope enabled with empty server address",
			configMap: map[string]string{
				"JWT_BUILDKITE_ORGANIZATION_SLUG":  "test-org",
				"BUILDKITE_API_TOKEN":              "test-token",
				"GITHUB_APP_ID":                    "123",
				"GITHUB_APP_INSTALLATION_ID":       "456",
				"GITHUB_APP_PRIVATE_KEY":           "test-key",
				"OBSERVE_PYROSCOPE_ENABLED":        "true",
				"OBSERVE_PYROSCOPE_SERVER_ADDRESS": "",
			},
			expectedErr: "invalid observe configuration",
		},
		{
			name: "pyroscope enabled with missing server address",
			configMap: map[string]string{
				"JWT_BUILDKITE_ORGANIZATION_SLUG": "test-org",
				"BUILDKITE_API_TOKEN":             "test-token",
				"GITHUB_APP_ID":                   "123",
				"GITHUB_APP_INSTALLATION_ID":      "456",
				"GITHUB_APP_PRIVATE_KEY":          "test-key",
				"OBSERVE_PYROSCOPE_ENABLED":       "true",
			},
			expectedErr: "invalid observe configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookuper := envconfig.MapLookuper(tt.configMap)
			_, err := load(context.Background(), lookuper)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestFileContentLookuper(t *testing.T) {
	dir := t.TempDir()

	pemPath := filepath.Join(dir, "private-key.pem")
	require.NoError(t, os.WriteFile(pemPath, []byte("file-key\n"), 0o600))

	missingPath := filepath.Join(dir, "does-not-exist")

	blankPath := filepath.Join(dir, "blank")
	require.NoError(t, os.WriteFile(blankPath, []byte("  \n\t\n"), 0o600))

	tests := []struct {
		name string
		// base seeds the wrapped lookuper; allowedKeys restricts which keys the
		// "_FILE" convention applies to.
		base        map[string]string
		allowedKeys []string
		lookupKey   string
		wantValue   string
		wantOK      bool
		wantErr     string
	}{
		{
			name:        "allowed key with no value or file passes through unset",
			base:        map[string]string{},
			allowedKeys: []string{"GITHUB_APP_PRIVATE_KEY"},
			lookupKey:   "GITHUB_APP_PRIVATE_KEY",
			wantValue:   "",
			wantOK:      false,
		},
		{
			name:        "allowed key with inline value only passes through unchanged",
			base:        map[string]string{"GITHUB_APP_PRIVATE_KEY": "inline-key"},
			allowedKeys: []string{"GITHUB_APP_PRIVATE_KEY"},
			lookupKey:   "GITHUB_APP_PRIVATE_KEY",
			wantValue:   "inline-key",
			wantOK:      true,
		},
		{
			name:        "allowed key with _FILE only reads and trims file contents",
			base:        map[string]string{"GITHUB_APP_PRIVATE_KEY_FILE": pemPath},
			allowedKeys: []string{"GITHUB_APP_PRIVATE_KEY"},
			lookupKey:   "GITHUB_APP_PRIVATE_KEY",
			wantValue:   "file-key",
			wantOK:      true,
		},
		{
			name: "allowed key with both value and _FILE set is an error",
			base: map[string]string{
				"GITHUB_APP_PRIVATE_KEY":      "inline-key",
				"GITHUB_APP_PRIVATE_KEY_FILE": pemPath,
			},
			allowedKeys: []string{"GITHUB_APP_PRIVATE_KEY"},
			lookupKey:   "GITHUB_APP_PRIVATE_KEY",
			wantValue:   "inline-key",
			wantOK:      true,
			wantErr:     "GITHUB_APP_PRIVATE_KEY and GITHUB_APP_PRIVATE_KEY_FILE are mutually exclusive",
		},
		{
			name:        "allowed key with unreadable _FILE path is an error",
			base:        map[string]string{"GITHUB_APP_PRIVATE_KEY_FILE": missingPath},
			allowedKeys: []string{"GITHUB_APP_PRIVATE_KEY"},
			lookupKey:   "GITHUB_APP_PRIVATE_KEY",
			wantValue:   "",
			wantOK:      false,
			wantErr:     "read GITHUB_APP_PRIVATE_KEY_FILE",
		},
		{
			name:        "key outside the allowlist ignores its _FILE variant",
			base:        map[string]string{"VALKEY_PASSWORD_FILE": pemPath},
			allowedKeys: []string{"GITHUB_APP_PRIVATE_KEY"},
			lookupKey:   "VALKEY_PASSWORD",
			wantValue:   "",
			wantOK:      false,
		},
		{
			name:        "empty _FILE value is treated as unset",
			base:        map[string]string{"GITHUB_APP_PRIVATE_KEY_FILE": ""},
			allowedKeys: []string{"GITHUB_APP_PRIVATE_KEY"},
			lookupKey:   "GITHUB_APP_PRIVATE_KEY",
			wantValue:   "",
			wantOK:      false,
		},
		{
			name:        "whitespace-only _FILE content is an error",
			base:        map[string]string{"GITHUB_APP_PRIVATE_KEY_FILE": blankPath},
			allowedKeys: []string{"GITHUB_APP_PRIVATE_KEY"},
			lookupKey:   "GITHUB_APP_PRIVATE_KEY",
			wantValue:   "",
			wantOK:      false,
			wantErr:     "is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookuper := newFileContentLookuper(envconfig.MapLookuper(tt.base), tt.allowedKeys...)

			value, ok := lookuper.Lookup(tt.lookupKey)
			assert.Equal(t, tt.wantValue, value)
			assert.Equal(t, tt.wantOK, ok)

			if tt.wantErr == "" {
				assert.NoError(t, lookuper.Err())
			} else {
				require.Error(t, lookuper.Err())
				assert.Contains(t, lookuper.Err().Error(), tt.wantErr)
			}
		})
	}
}

func TestLoad_FileOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private-key.pem")
	require.NoError(t, os.WriteFile(path, []byte("file-key\n"), 0o600))

	configMap := map[string]string{
		"JWT_BUILDKITE_ORGANIZATION_SLUG": "test-org",
		"BUILDKITE_API_TOKEN":             "test-token",
		"GITHUB_APP_ID":                   "123",
		"GITHUB_APP_INSTALLATION_ID":      "456",
		"GITHUB_APP_PRIVATE_KEY_FILE":     path,
	}
	lookuper := newFileContentLookuper(
		envconfig.MapLookuper(configMap), "JWT_JWKS_STATIC", "GITHUB_APP_PRIVATE_KEY",
	)

	cfg, err := load(context.Background(), lookuper)
	require.NoError(t, err)
	assert.Equal(t, "file-key", cfg.Github.PrivateKey)
}

// TestLoad_FileOverrides_Error verifies that load surfaces a
// fileContentLookuper failure (here: an unreadable GITHUB_APP_PRIVATE_KEY_FILE
// path) as a wrapped "invalid configuration" error, rather than silently
// proceeding with a zero-value field.
func TestLoad_FileOverrides_Error(t *testing.T) {
	configMap := map[string]string{
		"JWT_BUILDKITE_ORGANIZATION_SLUG": "test-org",
		"BUILDKITE_API_TOKEN":             "test-token",
		"GITHUB_APP_ID":                   "123",
		"GITHUB_APP_INSTALLATION_ID":      "456",
		"GITHUB_APP_PRIVATE_KEY_FILE":     "/nonexistent/private-key.pem",
	}
	lookuper := newFileContentLookuper(
		envconfig.MapLookuper(configMap), "JWT_JWKS_STATIC", "GITHUB_APP_PRIVATE_KEY",
	)

	_, err := load(context.Background(), lookuper)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
	assert.Contains(t, err.Error(), "read GITHUB_APP_PRIVATE_KEY_FILE")
}

// TestLoad_RealEnvironment exercises the public Load entrypoint end to end:
// Load wires up the real OS environment lookuper (unlike load, which every
// other test drives with an explicit envconfig.Lookuper), so this is the
// only test that proves GITHUB_APP_PRIVATE_KEY_FILE and JWT_JWKS_STATIC_FILE
// actually reach the process environment main.go reads from in production.
//
// t.Setenv scopes every variable to this test and restores the prior
// environment on cleanup, so it cannot leak state into other tests even
// under `go test` process reuse.
func TestLoad_RealEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-key.pem")
	require.NoError(t, os.WriteFile(path, []byte("file-key\n"), 0o600))

	clearFileVars(t)
	for key, value := range requiredConfig {
		if key == "GITHUB_APP_PRIVATE_KEY" {
			continue // sourced from GITHUB_APP_PRIVATE_KEY_FILE below instead
		}
		t.Setenv(key, value)
	}
	t.Setenv("GITHUB_APP_PRIVATE_KEY_FILE", path)

	cfg, err := Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "file-key", cfg.Github.PrivateKey)
}

// TestLoad_RealEnvironment_GithubAppsFile proves GITHUB_APPS is in the
// allowlist Load builds, not just in a test-supplied one. Registry entries can
// carry an inline PEM private key, so an operator needs the same escape hatch
// from the process environment that the single-app private key has.
func TestLoad_RealEnvironment_GithubAppsFile(t *testing.T) {
	apps := `[{"name":"packages","appId":1,"installationId":2,"privateKey":"key"}]`

	path := filepath.Join(t.TempDir(), "apps.json")
	require.NoError(t, os.WriteFile(path, []byte(apps+"\n"), 0o600))

	clearFileVars(t)
	for key, value := range requiredConfig {
		t.Setenv(key, value)
	}
	t.Setenv("GITHUB_APPS_FILE", path)

	cfg, err := Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, apps, cfg.Github.Apps)
}

// TestLoad_RealEnvironment_GithubAppsConflict confirms GITHUB_APPS follows the
// same mutual-exclusion rule as the other allowlisted keys: two sources for one
// value leaves which app mints tokens ambiguous, so it fails rather than
// silently preferring one.
func TestLoad_RealEnvironment_GithubAppsConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apps.json")
	require.NoError(t, os.WriteFile(path, []byte("[]\n"), 0o600))

	clearFileVars(t)
	for key, value := range requiredConfig {
		t.Setenv(key, value)
	}
	t.Setenv("GITHUB_APPS", "[]")
	t.Setenv("GITHUB_APPS_FILE", path)

	_, err := Load(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
	assert.Contains(t, err.Error(), "GITHUB_APPS and GITHUB_APPS_FILE are mutually exclusive")
}

// clearFileVars removes every allowlisted key and its "_FILE" counterpart for
// the duration of the test. Load reads the real process environment, so a
// developer shell that already points one of these at a file (the repository's
// direnv profile sets JWT_JWKS_STATIC_FILE, for one) would otherwise decide
// the outcome of a test about a different variable.
func clearFileVars(t *testing.T) {
	t.Helper()

	for _, key := range []string{"JWT_JWKS_STATIC", "GITHUB_APP_PRIVATE_KEY", "GITHUB_APPS"} {
		unsetEnv(t, key)
		unsetEnv(t, key+"_FILE")
	}
}

// unsetEnv removes key from the environment for the duration of the test,
// restoring whatever value (or absence) preceded it on cleanup. This guards
// against the ambient test environment already defining key, which would
// otherwise make it look "set" to fileContentLookuper and falsely trip its
// mutual-exclusion check against a "_FILE" counterpart.
func unsetEnv(t *testing.T, key string) {
	t.Helper()

	if prior, ok := os.LookupEnv(key); ok {
		t.Cleanup(func() { require.NoError(t, os.Setenv(key, prior)) })
	}
	require.NoError(t, os.Unsetenv(key))
}
