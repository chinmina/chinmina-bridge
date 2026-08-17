package profile

import (
	"context"
	"fmt"
	"time"

	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

const (
	// refreshInterval is the period between background profile refreshes.
	refreshInterval = 5 * time.Minute

	// firstLoadRetryInterval is the delay between attempts to load the first
	// profile generation. It is much shorter than refreshInterval because the
	// service is not yet accepting connections while it retries: every wasted
	// second is time the deployment spends unavailable.
	firstLoadRetryInterval = 5 * time.Second
)

// AwaitFirstGeneration blocks until a profile generation has been loaded from
// the given location, retrying until it succeeds or the context is cancelled.
//
// Until a generation has loaded, the service has no configuration to serve:
// organization profile requests are answered with 404 and pipeline requests
// with a built-in permission set, while the instance reports healthy and counts
// as ready during a rolling deployment. Not listening is the readiness signal,
// which leaves the healthcheck contract unchanged.
//
// No timeout governs the wait. An unreachable or hung upstream blocks startup
// and the platform's own startup grace period is the backstop: a deadline of
// our own would be evidence about the platform rather than about the profile
// source. Each failed attempt is logged so the cause is visible while that
// plays out.
//
// The gate is a latch on the first load only. Once this returns, later loss of
// access to the profile source leaves the loaded generation in place and
// PeriodicRefresh keeps serving it.
func AwaitFirstGeneration(ctx context.Context, profileStore *ProfileStore, gh GitHubClient, orgProfileLocation string) error {
	for attempt := 1; ; attempt++ {
		err := refresh(ctx, profileStore, gh, orgProfileLocation)
		if err == nil {
			return nil
		}

		slog.Warn("waiting for first organization profile generation",
			"attempt", attempt,
			"location", orgProfileLocation,
			"error", err,
		)

		select {
		case <-time.After(firstLoadRetryInterval):
			// try again
		case <-ctx.Done():
			return fmt.Errorf("first organization profile load abandoned after %d attempt(s): %w", attempt, ctx.Err())
		}
	}
}

// PeriodicRefresh runs a background loop that refreshes profiles from the given
// location at regular intervals. Panics are recovered in the refresh function.
// The loop exits when the context is cancelled.
//
// The loop waits a full interval before its first refresh: AwaitFirstGeneration
// has already performed the first load synchronously before serving started, so
// refreshing immediately here would make every instance fetch the profile twice
// at boot.
func PeriodicRefresh(ctx context.Context, profileStore *ProfileStore, gh GitHubClient, orgProfileLocation string) {
	for {
		select {
		case <-time.After(refreshInterval):
			// continue
		case <-ctx.Done():
			slog.Info("refresh goroutine shutting down gracefully")
			return
		}

		if err := refresh(ctx, profileStore, gh, orgProfileLocation); err != nil {
			slog.Warn("organization profile refresh failed, continuing", "error", err)
		}
	}
}

// refresh performs a single profile refresh operation with tracing. A recovered
// panic is returned as an error rather than logged, so the caller decides how a
// failure is reported: a failed attempt means something different while the
// startup gate is waiting than it does once a generation is already being
// served.
func refresh(ctx context.Context, profileStore *ProfileStore, gh GitHubClient, orgProfileLocation string) (err error) {
	tracer := otel.Tracer("github.com/chinmina/chinmina-bridge/internal/profile")
	ctx, span := tracer.Start(ctx, "refresh_organization_profile")
	defer span.End()

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during profile refresh: %v", r)
			span.RecordError(err)
			span.SetStatus(codes.Error, "profile refresh panicked")
		}
	}()

	profiles, err := FetchOrganizationProfile(ctx, orgProfileLocation, gh)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "profile refresh failed")
		return err
	}

	profileStore.Update(ctx, profiles)
	span.SetStatus(codes.Ok, "profile refreshed")

	return nil
}
