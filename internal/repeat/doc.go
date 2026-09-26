// Package repeat schedules repeating background work.
// Task runs an action until cancellation and closes a readiness channel on its
// first success. It uses a startup interval before that success and a steady
// interval afterward, including after later failures.
//
// Task owns logging action failures. Callers own the action, cancellation,
// and any decision to gate service readiness on the first-success channel.
package repeat
