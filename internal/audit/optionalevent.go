package audit

import (
	"iter"

	"github.com/rs/zerolog"
)

type OptionalEvent struct {
	ev       *zerolog.Event
	modified bool
}

func NewOptionalEvent(e *zerolog.Event) *OptionalEvent {
	return &OptionalEvent{ev: e}
}

func (oe *OptionalEvent) event() *zerolog.Event {
	if oe.ev == nil {
		oe.ev = zerolog.Dict()
		oe.modified = false
	}
	return oe.ev

}

func (oe *OptionalEvent) Set(parent *zerolog.Event, key string) bool {
	if oe.modified {
		parent.Dict(key, oe.event())
		return true
	}
	return false
}

func (oe *OptionalEvent) Event() *zerolog.Event {
	e := oe.event()
	oe.modified = true
	return e
}

func (oe *OptionalEvent) Str(key, val string) *OptionalEvent {
	if val == "" {
		return oe
	}
	oe.event().Str(key, val)
	oe.modified = true
	return oe
}

func (oe *OptionalEvent) Strs(key string, vals []string) *OptionalEvent {
	if len(vals) == 0 {
		return oe
	}
	oe.event().Strs(key, vals)
	oe.modified = true
	return oe
}

func (oe *OptionalEvent) Bool(key string, val bool) *OptionalEvent {
	oe.event().Bool(key, val)
	oe.modified = true
	return oe
}

func (oe *OptionalEvent) Int(key string, val int) *OptionalEvent {
	if val == 0 {
		return oe
	}
	oe.event().Int(key, val)
	oe.modified = true
	return oe
}

func arr[T zerolog.LogObjectMarshaler](vals []T) iter.Seq[zerolog.LogObjectMarshaler] {
	if vals == nil {
		return nil
	}

	return func(yield func(zerolog.LogObjectMarshaler) bool) {
		if len(vals) == 0 {
			return
		}

		for _, v := range vals {
			if !yield(v) {
				return
			}
		}
	}
}

func (oe *OptionalEvent) Arr(key string, val iter.Seq[zerolog.LogObjectMarshaler]) *OptionalEvent {
	if val == nil {
		return oe
	}

	arr := zerolog.Arr()
	for v := range val {
		arr.Object(v)
	}

	oe.event().Array(key, arr)
	oe.modified = true

	return oe
}
