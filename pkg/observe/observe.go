// Package observe provides opt-in runtime observability for scans:
// throttled progress callbacks, structured errors and cancellation handling.
//
// Nothing in this package is active unless a Tracker is explicitly created
// through [WithTracker] and stored in the context. When no tracker is present
// all helpers are no-ops and the default scan behavior is unchanged.
package observe

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
)

// Stage identifies the phase a progress event belongs to.
type Stage string

const (
	// StageImageLayers is emitted while container image layers are analyzed.
	StageImageLayers Stage = "image_layers"
	// StageFiles is emitted while filesystem/repository files are analyzed.
	StageFiles Stage = "files"
	// StageScan is emitted during the vulnerability/misconfig evaluation.
	StageScan Stage = "scan"
)

// Progress is a point-in-time snapshot of a scan's advancement.
//
// Total is zero when the total amount of work cannot be determined up front
// (e.g. streaming input). In that case Current still advances and callers must
// treat the task as having an unknown total rather than as zero work.
type Progress struct {
	// Stage is the phase that produced this snapshot.
	Stage Stage `json:"stage"`
	// Current is the amount of work already processed. It never decreases.
	Current int64 `json:"current"`
	// Total is the total amount of work. It is zero when the total is unknown.
	Total int64 `json:"total,omitempty"`
	// BytesProcessed / BytesTotal mirror Current/Total but count bytes. They are
	// best-effort and zero when byte accounting is unavailable.
	BytesProcessed int64 `json:"bytes_processed,omitempty"`
	BytesTotal     int64 `json:"bytes_total,omitempty"`
	// Elapsed is the time since the Tracker was started.
	Elapsed time.Duration `json:"elapsed"`
	// Timestamp is when the snapshot was emitted.
	Timestamp time.Time `json:"timestamp"`
}

// ProgressCallback receives progress snapshots.
//
// Callbacks are invoked synchronously from the scanning goroutine, so they
// must return quickly. A panicking callback is recovered and logged; it never
// aborts the scan.
type ProgressCallback func(Progress)

// Options configures a Tracker.
type Options struct {
	// Callback receives throttled progress events. Required to enable tracking.
	Callback ProgressCallback
	// Interval is the minimum duration between two callbacks. Zero means every
	// event is delivered. The first event and the completion event are always
	// delivered regardless of the interval.
	Interval time.Duration
	// now is injectable for tests; nil uses time.Now.
	now func() time.Time
}

type trackerKey struct{}

// Tracker aggregates scan progress and fans it out to a single callback at a
// fixed cadence. It is safe for concurrent use.
//
// The tracker holds only fixed-size counters, so memory usage stays constant
// no matter how long a scan runs or how many events are produced.
type Tracker struct {
	callback ProgressCallback
	interval time.Duration
	now      func() time.Time

	startedAt time.Time

	current        atomic.Int64
	total          atomic.Int64
	bytesProcessed atomic.Int64
	bytesTotal     atomic.Int64
	stage          atomic.Value

	mu        sync.Mutex
	lastEmit  time.Time
	lastValue int64
	closed    bool
}

// NewTracker creates a Tracker. A nil callback returns a no-op tracker.
func NewTracker(opts Options) *Tracker {
	now := opts.now
	if now == nil {
		now = time.Now
	}
	t := &Tracker{
		callback:  opts.Callback,
		interval:  opts.Interval,
		now:       now,
		startedAt: now(),
	}
	t.stage.Store(StageScan)
	if t.callback == nil {
		// Keep a usable zero object but make dispatch a no-op.
		t.callback = func(Progress) {}
	}
	t.lastEmit = t.startedAt
	return t
}

// WithTracker returns a child context carrying the tracker.
func WithTracker(ctx context.Context, t *Tracker) context.Context {
	if t == nil {
		return ctx
	}
	return context.WithValue(ctx, trackerKey{}, t)
}

// FromContext returns the tracker registered on ctx, or nil.
func FromContext(ctx context.Context) *Tracker {
	t, _ := ctx.Value(trackerKey{}).(*Tracker)
	return t
}

// SetTotal records the total amount of work for a stage. It may be called with
// zero to indicate an unknown total (streaming inputs).
func (t *Tracker) SetTotal(stage Stage, total int64) {
	if t == nil {
		return
	}
	t.stage.Store(stage)
	t.total.Store(total)
	t.mu.Lock()
	t.closed = false
	t.mu.Unlock()
	t.emit(false)
}

// SetBytesTotal records the total amount of bytes, when known.
func (t *Tracker) SetBytesTotal(bytes int64) {
	if t == nil {
		return
	}
	t.bytesTotal.Store(bytes)
}

// Add advances the processed counter and emits a throttled event.
func (t *Tracker) Add(delta int64) {
	if t == nil {
		return
	}
	t.current.Add(delta)
	t.emit(false)
}

// AddBytes accounts for processed bytes without changing the unit counters.
func (t *Tracker) AddBytes(delta int64) {
	if t == nil {
		return
	}
	t.bytesProcessed.Add(delta)
	t.emit(false)
}

// Finish forces emission of the final snapshot and marks the stage complete.
// It is safe to call multiple times.
func (t *Tracker) Finish() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()
	t.emit(true)
}

// Snapshot returns the current progress without invoking the callback.
func (t *Tracker) Snapshot() Progress {
	if t == nil {
		return Progress{}
	}
	return t.snapshot()
}

func (t *Tracker) snapshot() Progress {
	now := t.now()
	stage, _ := t.stage.Load().(Stage)
	return Progress{
		Stage:          stage,
		Current:        t.current.Load(),
		Total:          t.total.Load(),
		BytesProcessed: t.bytesProcessed.Load(),
		BytesTotal:     t.bytesTotal.Load(),
		Elapsed:        now.Sub(t.startedAt),
		Timestamp:      now,
	}
}

// emit dispatches the snapshot unless the interval has not elapsed. The first
// event of a stage and forced (completion) events bypass throttling.
func (t *Tracker) emit(force bool) {
	now := t.now()

	t.mu.Lock()
	if !force && t.interval > 0 && t.lastValue != 0 &&
		now.Sub(t.lastEmit) < t.interval {
		t.mu.Unlock()
		return
	}
	p := t.snapshot()
	t.lastEmit = now
	t.lastValue = p.Current
	cb := t.callback
	t.mu.Unlock()

	t.dispatch(cb, p)
}

// dispatch runs the callback with panic recovery so a faulty callback can never
// take the scan down.
func (t *Tracker) dispatch(cb ProgressCallback, p Progress) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Progress callback panicked; continuing the scan",
				log.Any("panic", r))
		}
	}()
	cb(p)
}
