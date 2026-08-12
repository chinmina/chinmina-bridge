package vendor

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

// RepositoryTarget is what a request resolves to at the GitHub boundary: the
// repositories a token may cover, the permissions it carries, and the URL the
// token is vended for. Matched is false when the request is understood but no
// credentials apply — a repository outside the profile's reach — which is a
// successful no-credentials answer, not an error.
//
// Permissions are copied verbatim from the resolved profile by every resolver.
// The field exists so the whole GitHub request travels as one value, not so a
// resolver can choose privilege: a resolver decides which repositories a
// request reaches, never what may be done to them.
type RepositoryTarget struct {
	Scope       profile.RepositoryScope
	VendedURL   string
	Permissions []string
	Matched     bool
}

// noRepositories is the target for a request that is understood but reaches no
// repository the profile covers. It is named because Matched is false in the
// zero value: a bare RepositoryTarget{} return reads like a forgotten branch.
func noRepositories() (RepositoryTarget, error) {
	return RepositoryTarget{}, nil
}

// RepositoryResolver determines the repository target for a resolved request.
// It is the only family-specific part of vending: organization profiles read
// their repository set from the profile, pipeline profiles ask Buildkite which
// repository the pipeline is attached to.
type RepositoryResolver[T any] func(ctx context.Context, r Resolved[T], requestedRepoURL string) (RepositoryTarget, error)

// Vending issues the token for a resolved request. It holds no configuration:
// the resolved profile supplies the scope and permissions, so the token can
// only ever describe the profile generation the request was authorized
// against.
func Vending[T any](resolve RepositoryResolver[T], tokenVendor TokenVendor) ProfileTokenVendor[T] {
	return func(ctx context.Context, r Resolved[T], requestedRepoURL string) VendorResult {
		target, err := resolve(ctx, r, requestedRepoURL)
		if err != nil {
			return NewVendorFailed(err)
		}
		if !target.Matched {
			return NewVendorUnmatched()
		}

		// GitHub omits an empty repository list from the request, and reads its
		// absence as every repository in the installation. Only a wildcard may
		// ask for that, and it says so explicitly: every other scope kind is
		// resolved to concrete names before it gets here — caller-scoped
		// included, which is narrowed to the requested repository. An empty
		// list on a non-wildcard scope is therefore a resolver defect, and
		// vending it would grant the whole installation, so fail instead.
		// Vending is exported and RepositoryResolver is an extension point.
		if !target.Scope.IsWildcard() && len(target.Scope.Names) == 0 {
			return NewVendorFailed(fmt.Errorf("no repository scope resolved for profile %s", r.Ref))
		}

		// A wildcard scope carries a nil repository list, and GitHub reads nil
		// as "every repository in the installation" — the intended
		// all-repositories behaviour. Do not "fix" this into an empty slice.
		token, expiry, err := tokenVendor(ctx, target.Scope.Names, target.Permissions)
		if err != nil {
			return NewVendorFailed(fmt.Errorf("could not issue token for profile %s (repositories %v): %w", r.Ref, target.Scope.NamesForDisplay(), err))
		}

		slog.Info("profile token issued",
			"organization", r.Ref.Organization,
			"profile", r.Ref.ShortString(),
		)

		return NewVendorSuccess(ProfileToken{
			OrganizationSlug:    r.Ref.Organization,
			VendedRepositoryURL: target.VendedURL,
			Repositories:        target.Scope,
			Permissions:         target.Permissions,
			Profile:             r.Ref.ShortString(),
			Token:               token,
			HashedToken:         HashToken(token),
			Expiry:              expiry,
		})
	}
}

// OrgRepositories resolves the repository target for organization-scoped
// (org:*) profiles, used by the /organization/token/{profile} and
// /organization/git-credentials/{profile} routes. The repository set comes
// from the resolved profile; nothing is looked up.
func OrgRepositories(_ context.Context, r Resolved[profile.OrganizationProfileAttr], requestedRepoURL string) (RepositoryTarget, error) {
	profileScope := r.Profile.Attrs.RepositoryScope()

	scope, err := resolveRequestScope(profileScope, r.Ref)
	if err != nil {
		return RepositoryTarget{}, err
	}

	target := RepositoryTarget{
		Scope:       scope,
		VendedURL:   requestedRepoURL,
		Permissions: r.Profile.Attrs.Permissions,
		Matched:     true,
	}

	// At the git-credentials endpoint a non-caller-scoped profile must still
	// cover the repository git asked about. Caller-scoped profiles were
	// narrowed to it above; wildcard profiles claim every repository.
	if requestedRepoURL == "" || profileScope.IsCallerScoped() || profileScope.IsWildcard() {
		return target, nil
	}

	repo, err := url.Parse(requestedRepoURL)
	if err != nil {
		return RepositoryTarget{}, fmt.Errorf("could not parse requested repo URL %s: %w", requestedRepoURL, err)
	}

	if _, repository := github.RepoForURL(*repo); !scope.Contains(repository) {
		slog.Debug("profile doesn't support requested repository: no token vended.",
			"organization", r.Ref.Organization,
			"profile", r.Ref.ShortString(),
			"requestedRepo", requestedRepoURL,
		)
		return noRepositories()
	}

	return target, nil
}

// PipelineRepositories returns the repository resolver for pipeline-scoped
// (repo:*) profiles, used by the /token and /git-credentials routes. The
// repository is the one Buildkite says the pipeline is attached to; the
// profile supplies only the permissions.
func PipelineRepositories(repoLookup RepositoryLookup) RepositoryResolver[profile.PipelineProfileAttr] {
	return func(ctx context.Context, r Resolved[profile.PipelineProfileAttr], requestedRepoURL string) (RepositoryTarget, error) {
		pipelineRepoURL, err := repoLookup(ctx, r.Ref.Organization, r.Ref.PipelineSlug)
		if err != nil {
			return RepositoryTarget{}, fmt.Errorf("could not find repository for pipeline %s: %w", r.Ref.PipelineSlug, err)
		}

		// The pipeline itself may be configured for SSH, and changed by the
		// agent. For comparison purposes here it has to be an HTTPS URL.
		pipelineRepoURL = TranslateSSHToHTTPS(pipelineRepoURL)

		if requestedRepoURL != "" && pipelineRepoURL != requestedRepoURL {
			// A repository mismatch means we should not return a token or an
			// error: Git uses this to determine it should try the next
			// provider.
			slog.Debug("profile doesn't support requested repository: no token vended.",
				"organization", r.Ref.Organization,
				"profile", r.Ref.ShortString(),
				"repo", pipelineRepoURL,
				"requestedRepo", requestedRepoURL,
			)
			return noRepositories()
		}

		allowedRepoNames, err := github.GetRepoNames([]string{pipelineRepoURL})
		if err != nil {
			return RepositoryTarget{}, fmt.Errorf("error getting repo names: %w", err)
		}
		if len(allowedRepoNames) == 0 {
			return RepositoryTarget{}, fmt.Errorf("no valid repository names found for URL: %s", pipelineRepoURL)
		}

		return RepositoryTarget{
			Scope:       profile.NewSpecificScope(allowedRepoNames...),
			VendedURL:   pipelineRepoURL,
			Permissions: r.Profile.Attrs.Permissions,
			Matched:     true,
		}, nil
	}
}

// resolveRequestScope determines the effective repository scope for a request.
// Scope validation happens at the handler boundary (in NewOrgProfileResolver);
// here we simply interpret the ref's ScopedRepository against the profile's
// declared scope.
func resolveRequestScope(profileScope profile.RepositoryScope, ref profile.ProfileRef) (profile.RepositoryScope, error) {
	if profileScope.IsCallerScoped() {
		// The resolver is the enforcement point and guarantees ScopedRepository
		// is non-empty for caller-scoped refs. This guard keeps that invariant
		// local to the vendor (which is exported and could acquire other
		// callers) so an empty scope can never be vended as a token request for
		// the repository name "".
		if ref.ScopedRepository == "" {
			return profile.RepositoryScope{}, fmt.Errorf("caller-scoped profile %q requires a non-empty repository scope", ref.Name)
		}
		return profile.NewSpecificScope(ref.ScopedRepository), nil
	}

	return profileScope, nil
}
