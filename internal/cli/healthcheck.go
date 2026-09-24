package cli

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	urfave "github.com/urfave/cli/v3"
)

// UnhealthyError marks a probe that ran and found the service unhealthy, as
// distinct from a usage error, so the entry point reports it without
// suggesting help.
type UnhealthyError struct {
	Err error
}

func (e *UnhealthyError) Error() string { return e.Err.Error() }

func (e *UnhealthyError) Unwrap() error { return e.Err }

// defaultPort matches the service's SERVER_PORT default.
const defaultPort = "8080"

func healthcheckCommand() *urfave.Command {
	return &urfave.Command{
		Name:  "healthcheck",
		Usage: "probe a running service's health endpoint",
		Description: "Sends one GET request to the health endpoint and exits 0 only on an " +
			"HTTP 200 response. Any other status, a redirect, a connection failure or " +
			"the timeout exits 1 with a diagnostic on stderr. A successful probe prints " +
			"nothing. There are no retries: the caller owns the retry policy.\n\n" +
			"With --url, the probe targets that URL exactly and ignores --port and " +
			"--base-path. Otherwise it targets http://127.0.0.1:PORT/PATH/healthcheck, " +
			"built from the settings the service itself listens with. Command-line " +
			"flags take precedence over their environment variables.\n\n" +
			"No service configuration or credentials are needed, so a container health " +
			"check can invoke the binary directly, for example:\n\n" +
			"   [\"CMD\", \"/ko-app/chinmina-bridge\", \"healthcheck\"]",
		OnUsageError: returnUsageError,
		ArgValidator: noArguments,
		Flags: []urfave.Flag{
			&urfave.StringFlag{
				Name:      "url",
				Usage:     "probe this absolute http(s) `URL` instead of the local service",
				Validator: validateProbeURL,
			},
			&urfave.StringFlag{
				Name:    "port",
				Usage:   "`PORT` the local service listens on",
				Value:   defaultPort,
				Sources: urfave.EnvVars("SERVER_PORT"),
			},
			&urfave.StringFlag{
				Name:    "base-path",
				Usage:   "`PATH` prefix of the local service's routes",
				Sources: urfave.EnvVars("SERVER_BASE_PATH"),
			},
			&urfave.DurationFlag{
				Name:  "timeout",
				Usage: "fail if no response arrives within `DURATION`, e.g. 500ms or 3s",
				Value: 2 * time.Second,
				Validator: func(d time.Duration) error {
					if d <= 0 {
						return fmt.Errorf("timeout must be positive, got %s", d)
					}

					return nil
				},
			},
		},
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			target, err := probeTarget(cmd)
			if err != nil {
				return err
			}

			return probe(ctx, target, cmd.Duration("timeout"))
		},
	}
}

// probeTarget returns the explicit URL when given. Otherwise it addresses the
// service's health endpoint on loopback, from the same settings the service
// listens with. The port is parsed here rather than by the flag, so an invalid
// setting fails only a probe that uses it.
func probeTarget(cmd *urfave.Command) (string, error) {
	if cmd.IsSet("url") {
		return cmd.String("url"), nil
	}

	port, err := strconv.ParseUint(cmp.Or(cmd.String("port"), defaultPort), 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("invalid port %q", cmd.String("port"))
	}

	basePath, err := config.NormalizeBasePath(cmd.String("base-path"))
	if err != nil {
		return "", err
	}

	host := net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10))

	return "http://" + host + basePath + "/healthcheck", nil
}

func validateProbeURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url %q must use http or https", u.Redacted())
	}

	if u.Host == "" {
		return fmt.Errorf("url %q has no host", u.Redacted())
	}

	return nil
}

// probe issues a single GET to target, healthy only on a 200 response within
// timeout.
func probe(ctx context.Context, target string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}

	res, err := probeClient().Do(req)
	if err != nil {
		return &UnhealthyError{Err: err}
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return &UnhealthyError{Err: fmt.Errorf("GET %s: status %s", req.URL.Redacted(), res.Status)}
	}

	return nil
}

// probeClient is dedicated to the probe: it carries none of the service's
// instrumentation, and ignores proxy settings so a loopback probe stays local.
// A redirect is reported rather than followed: only the endpoint itself can
// declare the service healthy.
func probeClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
