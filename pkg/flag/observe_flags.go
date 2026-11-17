package flag

import "time"

var (
	// ObserveProgressFlag enables runtime progress callbacks. It is opt-in:
	// the default false keeps the historical behavior byte-for-byte identical.
	ObserveProgressFlag = Flag[bool]{
		Name:          "observe-progress",
		ConfigName:    "observe.progress.enabled",
		Usage:         "enable runtime progress callbacks and structured scan errors",
		TelemetrySafe: true,
	}
	// ObserveIntervalFlag sets the minimum callback cadence.
	ObserveIntervalFlag = Flag[time.Duration]{
		Name:          "observe-interval",
		ConfigName:    "observe.progress.interval",
		Default:       500 * time.Millisecond,
		Usage:         "minimum interval between progress callbacks (e.g. 500ms, 2s)",
		TelemetrySafe: true,
	}
)

// ObserveFlagGroup bundles runtime-observability flags.
type ObserveFlagGroup struct {
	ObserveProgress *Flag[bool]
	ObserveInterval *Flag[time.Duration]
}

// ObserveOptions is the resolved configuration for runtime observability.
// Enabled defaults to false, so scans behave exactly as before unless the
// capability is explicitly switched on.
type ObserveOptions struct {
	Enabled  bool
	Interval time.Duration
}

// NewObserveFlagGroup returns a default ObserveFlagGroup.
func NewObserveFlagGroup() *ObserveFlagGroup {
	return &ObserveFlagGroup{
		ObserveProgress: ObserveProgressFlag.Clone(),
		ObserveInterval: ObserveIntervalFlag.Clone(),
	}
}

func (f *ObserveFlagGroup) Name() string {
	return "Observe"
}

func (f *ObserveFlagGroup) Flags() []Flagger {
	return []Flagger{f.ObserveProgress, f.ObserveInterval}
}

func (f *ObserveFlagGroup) ToOptions(opts *Options) error {
	opts.ObserveOptions = ObserveOptions{
		Enabled:  f.ObserveProgress.Value(),
		Interval: f.ObserveInterval.Value(),
	}
	return nil
}
