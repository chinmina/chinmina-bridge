package profile

import (
	"context"
	"fmt"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/repeat"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

const (
	// refreshInterval is the period between refreshes once a generation is
	// being served.
	refreshInterval = 5 * time.Minute

	// firstLoadRetryInterval is the period between attempts before the first
	// generation loads. It is much shorter than refreshInterval because the
	// service is not yet accepting connections while it retries: every wasted
	// second is time the deployment spends unavailable. Once a generation is
	// being served that pressure is gone.
	firstLoadRetryInterval = 5 * time.Second
)

// RefreshTask returns the background task that keeps the store's profile
// generation current from the given location.
//
// The task's first success is the signal to start serving. Until a generation
// has loaded the service has no configuration to serve: organization profile
// requests are answered with 404 and pipeline requests with a built-in
// permission set, while the instance reports healthy and counts as ready
// during a rolling deployment.
//
// That signal is a latch on the first load only. Once it fires, later loss of
// access to the profile source leaves the loaded generation in place and the
// task keeps serving it.
func RefreshTask(profileStore *ProfileStore, gh GitHubClient, orgProfileLocation string) repeat.Task {
	return repeat.Task{
		Name:          "organization profile refresh",
		Attrs:         []any{"location", orgProfileLocation},
		FirstInterval: firstLoadRetryInterval,
		Interval:      refreshInterval,
		Action: func(ctx context.Context) error {
			return refresh(ctx, profileStore, gh, orgProfileLocation)
		},
	}
}

// refresh performs a single profile refresh operation with tracing. Failures,
// including a recovered panic, are returned rather than logged: the span
// records them here, and the task driving this reports them at its own single
// call site.
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
