package loginfra

import "log/slog"

// ReplaceLevel returns a ReplaceAttr function that maps custom slog levels to
// human-readable label strings. levels is a map from slog.Level to label.
// Standard levels (DEBUG, INFO, WARN, ERROR) and attrs inside groups pass
// through unchanged; unknown custom levels also pass through unchanged.
func ReplaceLevel(levels map[slog.Level]string) func([]string, slog.Attr) slog.Attr {
	return func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) > 0 || a.Key != slog.LevelKey {
			return a
		}

		level, ok := a.Value.Any().(slog.Level)
		if !ok {
			return a
		}

		if label, found := levels[level]; found {
			return slog.String(slog.LevelKey, label)
		}

		return a
	}
}
