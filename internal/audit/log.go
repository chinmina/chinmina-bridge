package audit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// marker for interface implementation
var _ zerolog.LogObjectMarshaler = (*Entry)(nil)

// marker for context key
type key struct{}

const (
	// Level is the log level at which audit logs are written.
	Level = zerolog.Level(20)
)

var (
	// logKey is the key used to store the audit log entry in the context.
	logKey = key{}
)

// ClaimMatch represents a successful claim match for audit logging.
type ClaimMatch struct {
	Claim string
	Value string
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler for ClaimMatch.
func (cm ClaimMatch) MarshalZerologObject(e *zerolog.Event) {
	e.Str("claim", cm.Claim).Str("value", cm.Value)
}

// ClaimFailure represents a failed claim match attempt for audit logging.
type ClaimFailure struct {
	Claim   string
	Pattern string
	Value   string
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler for ClaimFailure.
func (cf ClaimFailure) MarshalZerologObject(e *zerolog.Event) {
	e.Str("claim", cf.Claim).Str("pattern", cf.Pattern).Str("value", cf.Value)
}

// Entry is an audit log entry for the current request.
type Entry struct {
	Method              string
	Path                string
	Status              int
	SourceIP            string
	UserAgent           string
	RequestedProfile    string
	RequestedRepository string
	VendedRepository    string
	Authorized          bool
	AuthSubject         string
	AuthIssuer          string
	AuthAudience        []string
	AuthExpirySecs      int64
	OrganizationSlug    string
	PipelineSlug        string
	JobID               string
	BuildNumber         int
	BuildBranch         string
	Error               string
	Repositories        []string
	Permissions         []string
	ExpirySecs          int64
	ClaimsMatched       []ClaimMatch
	ClaimsFailed        []ClaimFailure
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler. This avoids the
// need for reflection when logging, at the cost of requiring maintenance when
// the Entry struct changes.
//
//nolint:gocyclo // marshaling function with many conditional fields
func (e *Entry) MarshalZerologObject(event *zerolog.Event) {

	// request fields
	event.Dict("request", zerolog.Dict().
		Str("method", e.Method).
		Str("path", e.Path).
		Int("status", e.Status).
		Str("sourceIP", e.SourceIP).
		Str("userAgent", e.UserAgent),
	)

	// pipeline/job details
	NewOptionalEvent(zerolog.Dict()).
		Str("pipelineSlug", e.PipelineSlug).
		Str("organizationSlug", e.OrganizationSlug).
		Str("jobID", e.JobID).
		Int("buildNumber", e.BuildNumber).
		Str("buildBranch", e.BuildBranch).
		Set(event, "pipeline")

	// JWT auth details
	authDetails := NewOptionalEvent(zerolog.Dict()).
		Bool("authorized", e.Authorized).
		Str("subject", e.AuthSubject).
		Str("issuer", e.AuthIssuer).
		Strs("audience", e.AuthAudience)

	now := time.Now()
	if e.AuthExpirySecs > 0 {
		exp := time.Unix(e.AuthExpirySecs, 0)
		remaining := exp.Sub(now).Round(time.Millisecond)
		authDetails.Event().Time("expiry", exp)
		authDetails.Event().Dur("expiryRemaining", remaining)
	}

	authDetails.Set(event, "authorization")

	// vended token details
	tokenDetails := NewOptionalEvent(zerolog.Dict()).
		Str("requestedProfile", e.RequestedProfile).
		Str("requestedRepository", e.RequestedRepository).
		Str("vendedRepository", e.VendedRepository).
		Strs("repositories", e.Repositories).
		Strs("permissions", e.Permissions).
		Arr("matches", arr(e.ClaimsMatched)).
		Arr("attemptedPatterns", arr(e.ClaimsFailed))

	if e.ExpirySecs > 0 {
		exp := time.Unix(e.ExpirySecs, 0)
		remaining := exp.Sub(now).Round(time.Millisecond)
		tokenDetails.Event().Time("expiry", exp)
		tokenDetails.Event().Dur("expiryRemaining", remaining)
	}

	tokenDetails.Set(event, "token")

	if e.Error != "" {
		event.Str("error", e.Error)
	}
}

// Begin sets up the audit log entry for the current request with details from the request.
func (e *Entry) Begin(r *http.Request) {
	e.Path = r.URL.Path
	e.Method = r.Method
	e.UserAgent = r.UserAgent()
	e.SourceIP = r.RemoteAddr
}

// End writes the audit log entry. If the returned func is deferred, any panic
// will be recovered so the log entry can be written before the panic is
// re-raised.
func (e *Entry) End(ctx context.Context) func() {
	return func() {
		// recover from panic if necessary
		r := recover()
		if r != nil {
			// record the details of the panic, attempting to avoid overwriting an
			// earlier error
			e.Status = http.StatusInternalServerError
			err := fmt.Sprintf("panic: %v", r)
			if e.Error != "" {
				e.Error += "; "
			}
			e.Error += err
		}

		// OK is the default if the status is not set when the response is written.
		if e.Status == 0 {
			e.Status = http.StatusOK
		}

		zerolog.Ctx(ctx).WithLevel(Level).EmbedObject(e).Str("type", "audit").Msg("audit_event")

		if r != nil {
			// repanic the panic
			panic(r)
		}
	}
}

// Middleware is an HTTP middleware that creates a new audit log entry for the
// current request and enriches it with information about the request. The log
// entry is written to the log when the request is complete.
//
// A panic during the request will be recovered and logged as an error in the
// audit entry. The HTTP status code of the response is also logged in the audit
// entry; further details may be added by the application.
func Middleware() func(next http.Handler) http.Handler {
	zerologConfiguration()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, entry := Context(r.Context())

			// wrap the response writer to capture the status code
			response := wrapResponseWriter(w, Log(ctx))

			entry.Begin(r)
			defer entry.End(ctx)()

			next.ServeHTTP(response, r.WithContext(ctx))
		})
	}
}

// Log gets the log entry for the current request. This is safe to use even if the
// context does not create an entry: it is never nil.
func Log(ctx context.Context) *Entry {
	_, e := Context(ctx)
	return e
}

// Context returns the Entry for the current request, creating one if it
// does not exist. If the returned context is kept, the returned entry can be
// further enriched. If not, information written to the entry will be lost.
func Context(ctx context.Context) (context.Context, *Entry) {
	e, ok := ctx.Value(logKey).(*Entry)
	if !ok {
		e = &Entry{}

		ctx = context.WithValue(ctx, logKey, e)
	}

	return ctx, e
}

func zerologConfiguration() {
	// configure the console writer
	zerolog.FormattedLevels[Level] = "AUD"

	// format the audit level as "audit", falling back to the default
	marshal := zerolog.LevelFieldMarshalFunc
	zerolog.LevelFieldMarshalFunc = func(l zerolog.Level) string {
		if l == Level {
			return "audit"
		}
		return marshal(l)
	}
}
