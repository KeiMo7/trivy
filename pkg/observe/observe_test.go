package observe

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTracker_ThrottledProgress(t *testing.T) {
	var mu sync.Mutex
	var got []Progress

	now := time.Now()
	tracker := NewTracker(Options{
		Callback: func(p Progress) {
			mu.Lock()
			got = append(got, p)
			mu.Unlock()
		},
		Interval: time.Hour, // large interval: only first + forced events pass
		now: func() time.Time {
			return now
		},
	})

	tracker.SetTotal(StageImageLayers, 5)
	for range 5 {
		tracker.Add(1)
	}
	tracker.Finish()

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(got), 2, "initial and completion events must always be delivered")

	first := got[0]
	assert.Equal(t, StageImageLayers, first.Stage)
	assert.Equal(t, int64(5), first.Total)

	last := got[len(got)-1]
	assert.Equal(t, int64(5), last.Current, "final snapshot must reflect all processed work")
	assert.LessOrEqual(t, last.Current, last.Total)
}

func TestTracker_CurrentMonotonicAndUnknownTotal(t *testing.T) {
	var got []Progress
	tracker := NewTracker(Options{
		Callback: func(p Progress) { got = append(got, p) },
		Interval: 0, // deliver every event
	})

	// Streaming input: total stays unknown.
	tracker.SetTotal(StageFiles, 0)
	for i := 1; i <= 4; i++ {
		tracker.Add(1)
	}
	tracker.Finish()

	require.Len(t, got, 6) // SetTotal + 4 adds + forced Finish
	for i, p := range got {
		assert.Equal(t, int64(0), p.Total, "streaming total must remain unknown")
		if i > 0 {
			assert.GreaterOrEqual(t, p.Current, got[i-1].Current, "current must be monotonic")
		}
	}
	assert.Equal(t, int64(4), got[len(got)-1].Current)
}

func TestTracker_CallbackPanicRecovered(t *testing.T) {
	tracker := NewTracker(Options{
		Callback: func(Progress) { panic("boom") },
	})

	assert.NotPanics(t, func() {
		tracker.SetTotal(StageScan, 2)
		tracker.Add(1)
		tracker.Finish()
	})
	assert.Equal(t, int64(1), tracker.Snapshot().Current)
}

func TestTracker_ConcurrentSafe(t *testing.T) {
	tracker := NewTracker(Options{
		Callback: func(Progress) {}, // swallow
		Interval: 0,
	})
	tracker.SetTotal(StageFiles, 1000)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				tracker.Add(1)
			}
		}()
	}
	wg.Wait()
	tracker.Finish()

	assert.Equal(t, int64(1000), tracker.Snapshot().Current)
}

func TestTracker_NilSafe(t *testing.T) {
	var tracker *Tracker
	assert.NotPanics(t, func() {
		tracker.SetTotal(StageScan, 1)
		tracker.Add(1)
		tracker.AddBytes(10)
		tracker.Finish()
		assert.Equal(t, Progress{}, tracker.Snapshot())
	})
}

func TestTracker_ContextRoundTrip(t *testing.T) {
	tracker := NewTracker(Options{Callback: func(Progress) {}})
	ctx := WithTracker(t.Context(), tracker)

	assert.Same(t, tracker, FromContext(ctx))
	assert.Nil(t, FromContext(t.Context()))
	assert.Same(t, tracker, FromContext(WithTracker(ctx, nil)))
}
