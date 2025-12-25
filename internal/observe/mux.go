package observe

import (
	"net/http"
	"slices"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type Multiplexer interface {
	Handle(pattern string, handler http.Handler)
	http.Handler
}

type Mux struct {
	wrapped Multiplexer
}

func NewMux(wrapped Multiplexer) *Mux {
	return &Mux{
		wrapped: wrapped,
	}
}

func (mux *Mux) Handle(pattern string, handler http.Handler) {
	// Configure the standard OTel handler along with route tagging for this
	// path
	taggedHandler := otelhttp.NewHandler(
		handler,
		TrimMethod(pattern),
	)

	mux.wrapped.Handle(pattern, taggedHandler)
}

func (mux *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux.wrapped.ServeHTTP(w, r)
}

var methods = []string{
	http.MethodConnect,
	http.MethodDelete,
	http.MethodGet,
	http.MethodHead,
	http.MethodOptions,
	http.MethodPatch,
	http.MethodPost,
	http.MethodPut,
	http.MethodTrace,
}

func TrimMethod(pattern string) string {
	method, resource, hasMethod := strings.Cut(pattern, " ")
	if hasMethod && slices.Contains(methods, method) {
		return resource
	}
	return pattern
}
