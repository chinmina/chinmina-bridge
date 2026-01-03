package config

import (
	"context"

	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	Authorization AuthorizationConfig
	Buildkite     BuildkiteConfig
	Github        GithubConfig
	Observe       ObserveConfig
	Server        ServerConfig
}

type ServerConfig struct {
	Port                   int `env:"SERVER_PORT, default=8080"`
	ShutdownTimeoutSeconds int `env:"SERVER_SHUTDOWN_TIMEOUT_SECS, default=25"`

	OutgoingHTTPMaxIdleConns    int    `env:"SERVER_OUTGOING_MAX_IDLE_CONNS, default=100"`
	OutgoingHTTPMaxConnsPerHost int    `env:"SERVER_OUTGOING_MAX_CONNS_PER_HOST, default=20"`
	OrgProfile                  string `env:"GITHUB_ORG_PROFILE"`
}

type AuthorizationConfig struct {
	Audience                  string `env:"JWT_AUDIENCE, default=app-token-issuer"`
	BuildkiteOrganizationSlug string `env:"JWT_BUILDKITE_ORGANIZATION_SLUG, required"`
	IssuerURL                 string `env:"JWT_ISSUER_URL, default=https://agent.buildkite.com"`
	ConfigurationStatic       string `env:"JWT_JWKS_STATIC"`
}

type BuildkiteConfig struct {
	APIURL string // internal only
	Token  string `env:"BUILDKITE_API_TOKEN, required"`
}

type GithubConfig struct {
	APIURL string // internal only

	PrivateKey    string `env:"GITHUB_APP_PRIVATE_KEY"`
	PrivateKeyARN string `env:"GITHUB_APP_PRIVATE_KEY_ARN"`

	ApplicationID  int64 `env:"GITHUB_APP_ID, required"`
	InstallationID int64 `env:"GITHUB_APP_INSTALLATION_ID, required"`
}

type ObserveConfig struct {
	SDKLogLevel                string `env:"OBSERVE_OTEL_LOG_LEVEL, default=info"`
	Enabled                    bool   `env:"OBSERVE_ENABLED, default=false"`
	MetricsEnabled             bool   `env:"OBSERVE_METRICS_ENABLED, default=true"`
	Type                       string `env:"OBSERVE_TYPE, default=grpc"`
	ServiceName                string `env:"OBSERVE_SERVICE_NAME, default=chinmina-bridge"`
	TraceBatchTimeoutSeconds   int    `env:"OBSERVE_TRACE_BATCH_TIMEOUT_SECS, default=20"`
	MetricReadIntervalSeconds  int    `env:"OBSERVE_METRIC_READ_INTERVAL_SECS, default=60"`
	HTTPTransportEnabled       bool   `env:"OBSERVE_HTTP_TRANSPORT_ENABLED, default=true"`
	HTTPConnectionTraceEnabled bool   `env:"OBSERVE_CONNECTION_TRACE_ENABLED, default=true"`
}

func Load(ctx context.Context) (cfg Config, err error) {
	err = envconfig.Process(ctx, &cfg)
	return
}
