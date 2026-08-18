package vendor_test

import (
	"context"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// A name is a label on an identity, and an operator may repoint it. The YAML —
// and so the digest — is unchanged when they do, so a key that carried only
// the digest would keep serving tokens minted through the previous app. These
// tests assert observable cache behaviour rather than the key string: the key
// format is an implementation detail, but "these two requests must not share
// an entry" is the guarantee.
func TestCached_AppIdentityPartitionsTheCache(t *testing.T) {
	ref := profile.ProfileRef{
		Organization: "acme",
		Type:         profile.ProfileTypeOrg,
		Name:         "publish",
	}

	tests := []struct {
		name   string
		first  github.AppIdentity
		second github.AppIdentity
		shared bool
	}{
		{
			name:   "different installations of one application do not share entries",
			first:  github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 444},
			second: github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 555},
		},
		{
			name:   "different applications do not share entries",
			first:  github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 444},
			second: github.AppIdentity{Name: "deploy", ApplicationID: 777, InstallationID: 444},
		},
		{
			// The key carries identity rather than name, so two names for one
			// application and installation are one cache entry, differing only
			// in attribution.
			name:   "two names for one identity share entries",
			first:  github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 444},
			second: github.AppIdentity{Name: "publishing", ApplicationID: 333, InstallationID: 444},
			shared: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mints := 0
			cached := newTestCached(t, 45*time.Minute)(func(_ context.Context, r vendor.Resolved[cacheAttr], _ string) vendor.VendorResult {
				mints++
				return vendor.NewVendorSuccess(vendor.ProfileToken{
					Profile: r.Ref.ShortString(),
					App:     r.App.Name,
					Token:   "token-for-" + r.App.Name,
					Expiry:  time.Now().Add(time.Hour),
				})
			})

			first := vendor.Resolved[cacheAttr]{Ref: ref, Digest: testGeneration, App: tt.first}
			second := vendor.Resolved[cacheAttr]{Ref: ref, Digest: testGeneration, App: tt.second}

			firstResult := cached(t.Context(), first, "")
			secondResult := cached(t.Context(), second, "")

			require.Equal(t, vendor.VendStatusSuccess, firstResult.Status())
			require.Equal(t, vendor.VendStatusSuccess, secondResult.Status())

			if tt.shared {
				assert.Equal(t, 1, mints, "one identity is one cache entry")
				assert.Equal(t, "token-for-"+tt.first.Name, secondResult.Token().Token,
					"the second request must be served the first's entry")
				return
			}

			assert.Equal(t, 2, mints, "each identity must mint its own token")
			assert.Equal(t, "token-for-"+tt.second.Name, secondResult.Token().Token,
				"the second request must not be served the first's token")
		})
	}
}

// The cached payload is the response, so a cache hit and a cache miss must
// carry the same attribution. Without this a caller could not tell which app
// minted a token it was served warm.
func TestCached_HitCarriesTheMintingApp(t *testing.T) {
	app := github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 444}

	cached := newTestCached(t, 45*time.Minute)(func(_ context.Context, r vendor.Resolved[cacheAttr], _ string) vendor.VendorResult {
		return vendor.NewVendorSuccess(vendor.ProfileToken{
			App:    r.App.Name,
			Token:  "minted",
			Expiry: time.Now().Add(time.Hour),
		})
	})

	request := vendor.Resolved[cacheAttr]{
		Ref:    profile.ProfileRef{Organization: "acme", Type: profile.ProfileTypeOrg, Name: "publish"},
		Digest: testGeneration,
		App:    app,
	}

	miss := cached(t.Context(), request, "")
	hit := cached(t.Context(), request, "")

	assert.Equal(t, "packages", miss.Token().App)
	assert.Equal(t, miss.Token(), hit.Token(), "a hit and a miss must return the same shape")
}

// An unresolved identity would key every app's entries together under zeroes,
// which is precisely the collision the key exists to prevent. Refusing is the
// only safe answer: defaulting would silently serve one app's token through
// another's key.
func TestCached_RefusesAnUnresolvedAppIdentity(t *testing.T) {
	cached := newTestCached(t, 45*time.Minute)(func(context.Context, vendor.Resolved[cacheAttr], string) vendor.VendorResult {
		t.Fatal("the wrapped vendor must not be reached")
		return vendor.VendorResult{}
	})

	result := cached(t.Context(), vendor.Resolved[cacheAttr]{
		Ref:    profile.ProfileRef{Organization: "acme", Type: profile.ProfileTypeOrg, Name: "publish"},
		Digest: testGeneration,
	}, "")

	assertVendorFailure(t, result, "no app identity resolved")
}

// The cache outcome metric is attributed with the app, so a partly-cold cache
// can be attributed to the app whose entries were orphaned rather than read as
// a service-wide regression.
func TestCached_OutcomeMetricIsAttributedWithTheApp(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(previous) })

	cached := newTestCached(t, 45*time.Minute)(func(_ context.Context, r vendor.Resolved[cacheAttr], _ string) vendor.VendorResult {
		return vendor.NewVendorSuccess(vendor.ProfileToken{App: r.App.Name, Token: "minted", Expiry: time.Now().Add(time.Hour)})
	})

	request := vendor.Resolved[cacheAttr]{
		Ref:    profile.ProfileRef{Organization: "acme", Type: profile.ProfileTypeOrg, Name: "publish"},
		Digest: testGeneration,
		App:    github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 444},
	}

	cached(t.Context(), request, "") // miss
	cached(t.Context(), request, "") // hit

	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &collected))

	outcomes := map[string]string{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			sum, isSum := m.Data.(metricdata.Sum[int64])
			if m.Name != "token.cache.outcome" || !isSum {
				continue
			}
			for _, point := range sum.DataPoints {
				result, _ := point.Attributes.Value("token.cache.result")
				app, _ := point.Attributes.Value("token.app")
				outcomes[result.AsString()] = app.AsString()
			}
		}
	}

	assert.Equal(t, map[string]string{"miss": "packages", "hit": "packages"}, outcomes)
}
