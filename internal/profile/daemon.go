package profile

import (
	"context"
	"fmt"
	"time"

	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

// PeriodicRefresh runs a background loop that refreshes profiles from the given
// location at regular intervals. Panics are recovered in the refresh function.
// The loop exits when the context is cancelled.
func PeriodicRefresh(ctx context.Context, profileStore *ProfileStore, gh GitHubClient, orgProfileLocation string) {
	for {
		refresh(ctx, profileStore, gh, orgProfileLocation)

		select {
		case <-time.After(5 * time.Minute):
			// continue
		case <-ctx.Done():
			slog.Info("refresh goroutine shutting down gracefully")
			return
		}
	}
}

// refresh performs a single profile refresh operation with tracing.
func refresh(ctx context.Context, profileStore *ProfileStore, gh GitHubClient, orgProfileLocation string) {
	tracer := otel.Tracer("github.com/chinmina/chinmina-bridge/internal/profile")
	ctx, span := tracer.Start(ctx, "refresh_organization_profile")
	defer span.End()

	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic during profile refresh: %v", r)
			span.RecordError(err)
			span.SetStatus(codes.Error, "profile refresh panicked")
			slog.Warn("profile refresh panicked, recovered", "panic", r)
		}
	}()

	profiles, err := FetchOrganizationProfile(ctx, orgProfileLocation, gh)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "profile refresh failed")
		slog.Warn("organization profile refresh failed, continuing", "error", err)
		return
	}

	profileStore.Update(ctx, profiles)
	span.SetStatus(codes.Ok, "profile refreshed")
}
