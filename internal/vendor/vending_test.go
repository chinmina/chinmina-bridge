package vendor_test

import (
	"context"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var vendingExpiry = time.Date(2024, time.May, 7, 17, 59, 36, 0, time.UTC)

// recordingTokenVendor captures the repository names and permissions the
// GitHub call was asked for, which is the contract the resolvers determine.
func recordingTokenVendor(t *testing.T) (vendor.TokenVendor, *[]string, *[]string) {
	t.Helper()
	var gotRepos, gotPermissions []string
	v := vendor.TokenVendor(func(_ context.Context, repoNames, permissions []string) (string, time.Time, error) {
		gotRepos = repoNames
		gotPermissions = permissions
		return "minted-token", vendingExpiry, nil
	})
	return v, &gotRepos, &gotPermissions
}

func orgResolved(ref profile.ProfileRef, attrs profile.OrganizationProfileAttr) vendor.Resolved[profile.OrganizationProfileAttr] {
	return vendor.Resolved[profile.OrganizationProfileAttr]{
		Ref:     ref,
		Profile: profile.NewAuthorizedProfile(profile.CompositeMatcher(), attrs),
		Digest:  "test-digest",
	}
}

func pipelineResolved(ref profile.ProfileRef, attrs profile.PipelineProfileAttr) vendor.Resolved[profile.PipelineProfileAttr] {
	return vendor.Resolved[profile.PipelineProfileAttr]{
		Ref:     ref,
		Profile: profile.NewAuthorizedProfile(profile.CompositeMatcher(), attrs),
		Digest:  "test-digest",
	}
}

// TestVending_OrgPermissionsComeFromResolvedProfile checks that the vendor
// issues the permissions carried by the request's resolved profile. Reading
// them from the store again would let a refresh between authorization and
// vending mint a token the authorized generation never described.
func TestVending_OrgPermissionsComeFromResolvedProfile(t *testing.T) {
	tokenVendor, gotRepos, gotPermissions := recordingTokenVendor(t)
	v := vendor.Vending(vendor.OrgRepositories, tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "prod-deploy",
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewSpecificScope("widget", "gadget"),
		Permissions: []string{"contents:write"},
	}

	result := v(context.Background(), orgResolved(ref, attrs), "")

	require.Equal(t, vendor.VendStatusSuccess, result.Status())
	assert.Equal(t, []string{"widget", "gadget"}, *gotRepos)
	assert.Equal(t, []string{"contents:write"}, *gotPermissions)
	assert.Equal(t, vendor.ProfileToken{
		OrganizationSlug: "organization-slug",
		Repositories:     profile.NewSpecificScope("widget", "gadget"),
		Permissions:      []string{"contents:write"},
		Profile:          "org:prod-deploy",
		Token:            "minted-token",
		HashedToken:      vendor.HashToken("minted-token"),
		Expiry:           vendingExpiry,
	}, result.Token())
}

// TestVending_OrgWildcardPassesNilRepositories preserves the documented
// all-repositories behaviour: GitHub reads a nil repository list as "every
// repository in the installation", so it must not be normalised to an empty
// slice. This is also the other half of the empty-scope guard below — the
// guard rejects an empty repository list, and must not catch a wildcard.
func TestVending_OrgWildcardPassesNilRepositories(t *testing.T) {
	tokenVendor, gotRepos, _ := recordingTokenVendor(t)
	v := vendor.Vending(vendor.OrgRepositories, tokenVendor)

	ref := profile.ProfileRef{Organization: "organization-slug", Type: profile.ProfileTypeOrg, Name: "all-repos"}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewWildcardScope(),
		Permissions: []string{"contents:read"},
	}

	result := v(context.Background(), orgResolved(ref, attrs), "")

	require.Equal(t, vendor.VendStatusSuccess, result.Status())
	assert.Nil(t, *gotRepos)
}

// TestVending_OrgCallerScopedNarrowsToRequestedRepository checks the
// caller-scoped case still narrows the token to the single repository the ref
// carries, rather than the profile's declared scope literal.
func TestVending_OrgCallerScopedNarrowsToRequestedRepository(t *testing.T) {
	tokenVendor, gotRepos, _ := recordingTokenVendor(t)
	v := vendor.Vending(vendor.OrgRepositories, tokenVendor)

	ref := profile.ProfileRef{
		Organization:     "organization-slug",
		Type:             profile.ProfileTypeOrg,
		Name:             "caller-scoped",
		ScopedRepository: "target-repo",
	}
	attrs := profile.OrganizationProfileAttr{
		Scope:       profile.NewCallerScopedScope(),
		Permissions: []string{"contents:write"},
	}

	result := v(context.Background(), orgResolved(ref, attrs), "")

	require.Equal(t, vendor.VendStatusSuccess, result.Status())
	assert.Equal(t, []string{"target-repo"}, *gotRepos)
	assert.Equal(t, profile.NewSpecificScope("target-repo"), result.Token().Repositories)
}

// TestVending_PipelinePermissionsComeFromResolvedProfile is the pipeline
// analogue: the vendor issues the permissions carried by the resolved
// profile, not a fresh store read.
func TestVending_PipelinePermissionsComeFromResolvedProfile(t *testing.T) {
	tokenVendor, gotRepos, gotPermissions := recordingTokenVendor(t)
	repoLookup := vendor.RepositoryLookup(func(context.Context, string, string) (string, error) {
		return "https://github.com/organization-slug/widget", nil
	})
	v := vendor.Vending(vendor.PipelineRepositories(repoLookup), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "default",
		PipelineID:   "pipeline-id",
		PipelineSlug: "pipeline-slug",
	}
	attrs := profile.PipelineProfileAttr{Permissions: []string{"contents:read"}}

	result := v(context.Background(), pipelineResolved(ref, attrs), "")

	require.Equal(t, vendor.VendStatusSuccess, result.Status())
	assert.Equal(t, []string{"widget"}, *gotRepos)
	assert.Equal(t, []string{"contents:read"}, *gotPermissions)
	assert.Equal(t, "https://github.com/organization-slug/widget", result.Token().VendedRepositoryURL)
}

// TestVending_PipelineRejectsRepositoryOtherThanThePipelines keeps git's
// next-provider behaviour: a request for a repository the pipeline is not
// attached to yields no credentials.
func TestVending_PipelineRejectsRepositoryOtherThanThePipelines(t *testing.T) {
	tokenVendor, _, _ := recordingTokenVendor(t)
	repoLookup := vendor.RepositoryLookup(func(context.Context, string, string) (string, error) {
		return "https://github.com/organization-slug/widget", nil
	})
	v := vendor.Vending(vendor.PipelineRepositories(repoLookup), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "default",
		PipelineSlug: "pipeline-slug",
	}

	result := v(context.Background(), pipelineResolved(ref, profile.PipelineProfileAttr{}), "https://github.com/organization-slug/gadget")

	assert.Equal(t, vendor.VendStatusSuccessUnmatched, result.Status())
}

// TestVending_EmptyScopeFailsClosed guards the most expensive mistake
// available to this package: GitHub omits an empty repository list from the
// request and reads its absence as every repository in the installation. Only
// a wildcard may ask for that. Authorized rejects an empty profile before
// Vending sees it in the wired chain, and neither production resolver can
// produce an empty non-wildcard scope — but Vending is exported and
// RepositoryResolver is an extension point, so the leaf must fail closed.
func TestVending_EmptyScopeFailsClosed(t *testing.T) {
	emptyScopes := map[string]profile.RepositoryScope{
		"zero value":     {},
		"caller-scoped":  profile.NewCallerScopedScope(),
		"empty specific": profile.NewSpecificScope(),
	}

	for name, scope := range emptyScopes {
		t.Run(name, func(t *testing.T) {
			tokenVendor := vendor.TokenVendor(func(_ context.Context, repoNames []string, _ []string) (string, time.Time, error) {
				t.Errorf("token vendor must not be called for an empty repository scope; got repoNames=%v", repoNames)
				return "", time.Time{}, nil
			})

			// A third-party resolver, which is what the guard defends against:
			// the production resolvers cannot reach the mint with an empty
			// scope, so the target has to be supplied directly.
			resolve := vendor.RepositoryResolver[profile.OrganizationProfileAttr](
				func(context.Context, vendor.Resolved[profile.OrganizationProfileAttr], string) (vendor.RepositoryTarget, error) {
					return vendor.RepositoryTarget{Scope: scope, Permissions: []string{"contents:write"}, Matched: true}, nil
				},
			)
			v := vendor.Vending(resolve, tokenVendor)

			ref := profile.ProfileRef{Organization: "organization-slug", Type: profile.ProfileTypeOrg, Name: "empty"}

			result := v(context.Background(), vendor.Resolved[profile.OrganizationProfileAttr]{Ref: ref}, "")

			require.Equal(t, vendor.VendStatusFailed, result.Status())
			assert.ErrorContains(t, result.Err(), "no repository scope resolved")
		})
	}
}
