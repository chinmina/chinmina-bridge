package cache

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valkey-io/valkey-go"
)

func TestStaticCredentialsFn(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "returns configured credentials",
			username: "myuser",
			password: "mypass",
		},
		{
			name:     "works with empty credentials",
			username: "",
			password: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := StaticCredentialsFn(tt.username, tt.password)
			creds, err := fn(valkey.AuthCredentialsContext{})
			require.NoError(t, err)

			expected := valkey.AuthCredentials{
				Username: tt.username,
				Password: tt.password,
			}
			assert.Equal(t, expected, creds)
		})
	}
}

func testAWSConfig() aws.Config {
	return aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
	}
}

func TestIAMCredentialsFn(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.ValkeyConfig
	}{
		{
			name: "elasticache",
			cfg: config.ValkeyConfig{
				IAMEnabled:   true,
				Username:     "iam-user",
				IAMCacheName: "my-cluster",
			},
		},
		{
			name: "elasticache serverless",
			cfg: config.ValkeyConfig{
				IAMEnabled:    true,
				Username:      "iam-user",
				IAMCacheName:  "my-serverless-cache",
				IAMServerless: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := IAMCredentialsFn(tt.cfg, testAWSConfig())
			require.NoError(t, err)

			creds, err := fn(valkey.AuthCredentialsContext{})
			require.NoError(t, err)

			assert.Equal(t, tt.cfg.Username, creds.Username)
			assert.NotEmpty(t, creds.Password, "IAM token should be non-empty")
		})
	}
}
