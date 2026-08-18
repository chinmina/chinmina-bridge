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
	refreshInterval = 5 * time.Minute

	// Short, because startup blocks on this: every second spent retrying is a
	// second the deployment is unavailable.
	firstLoadRetryInterval = 5 * time.Second
)

// RefreshTask keeps the store's profile generation current. Callers gate
// startup on its first success.
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

// refresh loads one generation. Failures, including a recovered panic, are
// returned rather than logged: the span records them, and the task logs them.
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
