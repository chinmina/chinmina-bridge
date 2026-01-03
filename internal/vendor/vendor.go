package vendor

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/profile"
)

type ProfileTokenVendor func(ctx context.Context, ref profile.ProfileRef, repo string) VendorResult

// RepositoryLookup given a pipeline, returns the https version of the repository URL.
type RepositoryLookup func(ctx context.Context, organizationSlug, pipelineSlug string) (string, error)

// TokenVendor vends a token for the given repository URL. The URL must be a https URL to a
// GitHub repository that the vendor has permissions to access.
type TokenVendor func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error)

type ProfileToken struct {
	OrganizationSlug    string    `json:"organizationSlug"`
	Profile             string    `json:"profile"`
	VendedRepositoryURL string    `json:"repositoryUrl"`
	Repositories        []string  `json:"repositories"`
	Permissions         []string  `json:"permissions"`
	Token               string    `json:"token"`
	Expiry              time.Time `json:"expiry"`
}

func (t ProfileToken) URL() (*url.URL, error) {
	url, err := url.Parse(t.VendedRepositoryURL)
	if err != nil {
		return nil, err
	}

	if !url.IsAbs() {
		return nil, fmt.Errorf("repository URL must be absolute: %s", t.VendedRepositoryURL)
	}

	return url, nil
}

func (t ProfileToken) ExpiryUnix() string {
	return strconv.FormatInt(t.Expiry.UTC().Unix(), 10)
}

type VendStatus int

const (
	VendStatusSuccess VendStatus = iota
	VendStatusSuccessUnmatched
	VendStatusFailed
)

type VendorResult struct {
	status       VendStatus
	token        ProfileToken
	failureCause error
}

// NewVendorSuccess creates a VendorResult for successful token vending
func NewVendorSuccess(tok ProfileToken) VendorResult {
	return VendorResult{
		status: VendStatusSuccess,
		token:  tok,
	}
}

// NewVendorUnmatched creates a VendorResult for successful no match
func NewVendorUnmatched() VendorResult {
	return VendorResult{
		status: VendStatusSuccessUnmatched,
	}
}

// NewVendorFailed creates a VendorResult for vending failure
func NewVendorFailed(err error) VendorResult {
	return VendorResult{
		status:       VendStatusFailed,
		failureCause: err,
	}
}

// Failed returns the failure error if the vending failed
func (vr VendorResult) Failed() (error, bool) {
	if vr.status == VendStatusFailed {
		return vr.failureCause, true
	}
	return nil, false
}

// Token returns the vended token if vending succeeded with a match
func (vr VendorResult) Token() (ProfileToken, bool) {
	if vr.status == VendStatusSuccess {
		return vr.token, true
	}
	return ProfileToken{}, false
}

var sshUrl = regexp.MustCompile(`^git@github\.com:([^/].+)$`)

func TranslateSSHToHTTPS(url string) string {
	groups := sshUrl.FindStringSubmatch(url)
	if groups == nil {
		return url
	}

	return fmt.Sprintf("https://github.com/%s", groups[1])
}
