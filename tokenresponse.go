package main

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
)

// TokenResponseMarshaler fixes the response shape once from configuration: no
// request-time input decides what is disclosed, and the zero value withholds.
type TokenResponseMarshaler struct {
	disclose bool
}

func newTokenResponseMarshaler(withAppIdentity bool) TokenResponseMarshaler {
	return TokenResponseMarshaler{disclose: withAppIdentity}
}

// MarshalToken zeroes the identifiers on its own copy when withholding, so the
// payload's omitzero tags decide the shape and no second field list exists.
func (m TokenResponseMarshaler) MarshalToken(t vendor.ProfileToken) ([]byte, error) {
	if !m.disclose {
		t.ApplicationID, t.InstallationID = 0, 0
	}
	return json.Marshal(t)
}

// CredentialProperties renders the token in git's credential-helper format.
func (m TokenResponseMarshaler) CredentialProperties(t vendor.ProfileToken, u *url.URL) *credentialhandler.ArrayMap {
	props := credentialhandler.NewMap(9)

	props.Set("protocol", u.Scheme)
	props.Set("host", u.Host)
	props.Set("path", strings.TrimPrefix(u.Path, "/"))
	props.Set("username", "x-access-token")
	props.Set("password", t.Token)
	props.Set("password_expiry_utc", t.ExpiryUnix())

	if !m.disclose {
		return props
	}

	// gitcredentials(7) discards attributes it does not recognise, but a provided
	// attribute overwrites one git already knows: hence chinmina_.
	setNonEmpty(props, "chinmina_app_name", t.App)
	setNonEmpty(props, "chinmina_app_id", formatID(t.ApplicationID))
	setNonEmpty(props, "chinmina_installation_id", formatID(t.InstallationID))

	return props
}

// setNonEmpty mirrors omitzero: a value the token never carried is absent
// rather than present and blank.
func setNonEmpty(props *credentialhandler.ArrayMap, key, val string) {
	if val == "" {
		return
	}
	props.Set(key, val)
}

func formatID(id int64) string {
	if id == 0 {
		return ""
	}
	return strconv.FormatInt(id, 10)
}
