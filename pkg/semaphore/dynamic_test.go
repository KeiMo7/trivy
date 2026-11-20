package semaphore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDynamic_RejectsInvalidLimit(t *testing.T) {
	for _, limit := range []int{0, -1, -100} {
		_, err := NewDynamic(limit)
		assert.Error(t, err, "limit=%d must be rejected at construction", limit)
	}
}

func TestDynamicWeighted_EnforcesLimitUnderContention(t *testing.T) {
	const limit = 3
	sem, err := NewDynamic(limit)
	require.NoError(t, err)

	var (
		inUse     atomic.Int32
		maxInUse  atomic.Int32
		violation atomic.Bool
		wg        sync.WaitGroup
	)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			require.NoError(t, sem.Acquire(ctx, 1))
			cur := inUse.Add(1)
			for {
				seen := maxInUse.Load()
				if cur <= seen || maxInUse.CompareAndSwap(seen, cur) {
					break
				}
			}
			if cur > limit {
				violation.Store(true)
			}
			time.Sleep(time.Millisecond)
			inUse.Add(-1)
			sem.Release(1)
		}()
	}
	wg.Wait()

	assert.False(t, violation.Load(), "in-flight count must never exceed the configured limit")
	assert.Equal(t, int32(limit), maxInUse.Load())
	assert.Equal(t, 0, sem.InUse(), "all slots must be returned after every task finishes")
	assert.False(t, sem.Degraded())
}

func TestDynamicWeighted_ResizeDownLetsRunningFinish(t *testing.T) {
	sem, err := NewDynamic(4)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		require.NoError(t, sem.Acquire(ctx, 1))
	}
	assert.Equal(t, 4, sem.InUse())

	// Lower the limit while four slots are held: nothing is preempted.
	require.NoError(t, sem.Resize(1))
	assert.Equal(t, 1, sem.Limit())
	assert.Equal(t, 4, sem.InUse())

	// New acquisitions block even after one release, because 3 are still
	// above the new limit.
	sem.Release(1) // 3 held, still above the new limit of 1
	assert.False(t, sem.TryAcquire(1), "limit lowered to 1 while 3 slots remain held")

	got := make(chan struct{})
	go func() {
		_ = sem.Acquire(ctx, 1)
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("acquisition must stay blocked while usage exceeds the lowered limit")
	case <-time.After(20 * time.Millisecond):
	}

	sem.Release(1) // 2 held
	select {
	case <-got:
		t.Fatal("acquisition must stay blocked while 2 slots remain held under a limit of 1")
	case <-time.After(20 * time.Millisecond):
	}

	sem.Release(1) // 1 held: 1+1 still exceeds the limit of 1, waiter stays blocked
	select {
	case <-got:
		t.Fatal("acquisition must stay blocked while a slot is still held under a limit of 1")
	case <-time.After(20 * time.Millisecond):
	}

	sem.Release(1) // 0 held: the waiter now fits
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("the waiter must proceed once in-flight usage drains to the limit")
	}
	sem.Release(1) // the goroutine's slot
	assert.Equal(t, 0, sem.InUse())
}

func TestDynamicWeighted_ResizeUpWakesWaiters(t *testing.T) {
	sem, err := NewDynamic(1)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, sem.Acquire(ctx, 1))

	const waiters = 3
	var acquired atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, sem.Acquire(ctx, 1))
			acquired.Add(1)
		}()
	}

	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(0), acquired.Load(), "no waiter can fit under the old limit")

	require.NoError(t, sem.Resize(4))
	// One slot is held by the test itself; three waiters fit now.
	require.Eventually(t, func() bool { return acquired.Load() == waiters }, time.Second, time.Millisecond)

	sem.Release(1)
	for i := 0; i < waiters; i++ {
		sem.Release(1)
	}
	wg.Wait()
	assert.Equal(t, 0, sem.InUse())
}

func TestDynamicWeighted_ResizeRejectsInvalidLimit(t *testing.T) {
	sem, err := NewDynamic(2)
	require.NoError(t, err)
	for _, limit := range []int{0, -3} {
		assert.Error(t, sem.Resize(limit))
	}
	assert.Equal(t, 2, sem.Limit(), "failed resize must not change the active limit")
}

func TestDynamicWeighted_AcquireCanceledReleasesNoQuota(t *testing.T) {
	sem, err := NewDynamic(1)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, sem.Acquire(ctx, 1))

	subCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() { errCh <- sem.Acquire(subCtx, 1) }()

	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled Acquire must return")
	}

	// The canceled waiter leaves no trace: after releasing the held slot the
	// semaphore is empty and a fresh acquisition succeeds immediately.
	sem.Release(1)
	require.NoError(t, sem.Acquire(ctx, 1))
	assert.Equal(t, 1, sem.InUse())
	sem.Release(1)
	assert.Equal(t, 0, sem.InUse())
}

func TestDynamicWeighted_OverReleaseDegradesAndUnblocks(t *testing.T) {
	sem, err := NewDynamic(1)
	require.NoError(t, err)
	ctx := context.Background()

	// Corrupt the bookkeeping on purpose: release without an acquisition.
	sem.Release(1)
	assert.True(t, sem.Degraded(), "over-release must trigger degraded mode")

	// Degraded mode means unlimited, non-blocking acquisitions: the main
	// flow can never hang on a broken counter.
	require.NoError(t, sem.Acquire(ctx, 1))
	require.NoError(t, sem.Acquire(ctx, 1))
	sem.Release(1) // no-op, must not panic
}

func TestDynamicWeighted_FIFOOrder(t *testing.T) {
	sem, err := NewDynamic(1)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, sem.Acquire(ctx, 1))

	const n = 5
	order := make(chan int, n)
	enqueue := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i := <-enqueue // block until the test lets this waiter enter the queue
			require.NoError(t, sem.Acquire(ctx, 1))
			order <- i
			sem.Release(1)
		}()
	}

	// Release the waiters one by one so their Acquire calls enqueue in
	// a deterministic order.
	for i := 0; i < n; i++ {
		enqueue <- i
		time.Sleep(5 * time.Millisecond)
	}

	time.Sleep(30 * time.Millisecond)
	sem.Release(1) // release the head slot; the chain then drains itself
	wg.Wait()
	close(order)

	var got []int
	for i := range order {
		got = append(got, i)
	}
	assert.Equal(t, []int{0, 1, 2, 3, 4}, got, "waiters must be served in FIFO order")
}
