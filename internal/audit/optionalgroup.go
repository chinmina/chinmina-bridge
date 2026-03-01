package audit

import "log/slog"

// OptionalGroup is the slog equivalent of OptionalEvent: it collects slog
// attributes and only emits a named group when at least one attribute was
// added. This avoids empty groups in the structured log output.
type OptionalGroup struct {
	attrs    []slog.Attr
	modified bool
}

// NewOptionalGroup creates an empty OptionalGroup.
func NewOptionalGroup() *OptionalGroup {
	return &OptionalGroup{}
}

// Str adds a string attribute, skipping empty strings.
func (og *OptionalGroup) Str(key, val string) *OptionalGroup {
	if val == "" {
		return og
	}
	og.attrs = append(og.attrs, slog.String(key, val))
	og.modified = true
	return og
}

// Int adds an int attribute, skipping zero values.
func (og *OptionalGroup) Int(key string, val int) *OptionalGroup {
	if val == 0 {
		return og
	}
	og.attrs = append(og.attrs, slog.Int(key, val))
	og.modified = true
	return og
}

// Bool adds a bool attribute. Unlike Str/Int, zero (false) is not skipped,
// since false is a meaningful authorization state.
func (og *OptionalGroup) Bool(key string, val bool) *OptionalGroup {
	og.attrs = append(og.attrs, slog.Bool(key, val))
	og.modified = true
	return og
}

// Strs adds a string slice attribute, skipping nil and empty slices.
func (og *OptionalGroup) Strs(key string, vals []string) *OptionalGroup {
	if len(vals) == 0 {
		return og
	}
	og.attrs = append(og.attrs, slog.Any(key, vals))
	og.modified = true
	return og
}

// Attr is an escape hatch for types not covered by the typed methods (e.g.
// time.Time, time.Duration). It always marks the group as modified.
func (og *OptionalGroup) Attr(a slog.Attr) *OptionalGroup {
	og.attrs = append(og.attrs, a)
	og.modified = true
	return og
}

// Group returns a named group attribute when at least one attribute was added,
// otherwise it returns a zero slog.Attr (empty key). slog.JSONHandler omits
// empty-key attributes, so the group is elided when unmodified.
func (og *OptionalGroup) Group(key string) slog.Attr {
	if !og.modified {
		return slog.Attr{}
	}
	return slog.Attr{Key: key, Value: slog.GroupValue(og.attrs...)}
}
