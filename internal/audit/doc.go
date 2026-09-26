// Package audit records request outcomes for token-vending HTTP routes.
// Middleware attaches a mutable Entry to the request context, captures the
// response status, and emits the completed audit record independently of the
// application's ordinary log-level filtering.
//
// JWT validation, profile authorization, and vending enrich the same entry.
// If Context creates an entry, its returned context carries that entry to
// downstream code. The middleware belongs outside JWT validation so rejected
// assertions are audited too. Panics are recorded and then re-raised, not
// converted into successful requests.
package audit
