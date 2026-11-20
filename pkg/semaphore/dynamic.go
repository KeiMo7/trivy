package semaphore

import (
	"context"
	"sync"
	"sync/atomic"

	"golang.org/x/xerrors"
)

// DynamicWeighted is a weighted semaphore whose limit can be changed at runtime.
//
// A resize never interrupts acquisitions that are already held: running tasks
// finish naturally and release their slots, while new acquisitions obey the new
// limit. Lowering the limit below the number of currently held slots does not
// preempt anyone; once enough slots are released, further acquisitions block
// until in-flight usage drops under the new limit.
//
// All state transitions hold the same mutex, so two goroutines can never both
// observe a free slot and oversubscribe together. The zero value is not usable;
// construct it with NewDynamic.
type DynamicWeighted struct {
	mu sync.Mutex

	// limit is the current maximum number of concurrently held slots.
	limit int

	// inUse is the number of slots currently held.
	inUse int

	// waiters are goroutines blocked in Acquire, each with the number of
	// slots it requested and a channel closed once the request can proceed.
	// The slice itself is guarded by mu; signaling happens outside the lock
	// through the channel.
	waiters []dynamicWaiter

	// degraded switches the semaphore to unlimited mode. It is used when the
	// bookkeeping detects an inconsistent state so that the main scan flow
	// can never be blocked by a broken concurrency counter.
	degraded atomic.Bool
}

type dynamicWaiter struct {
	weight int
	ch     chan struct{}
}

// NewDynamic creates a DynamicWeighted with the given initial limit.
// It returns an error when limit is smaller than 1; callers must reject
// invalid configuration at startup rather than relying on a default here.
func NewDynamic(limit int) (*DynamicWeighted, error) {
	if limit < 1 {
		return nil, xerrors.Errorf("concurrency limit must be a positive integer, got %d", limit)
	}
	return &DynamicWeighted{limit: limit}, nil
}

// Acquire blocks until weight slots are available or ctx is canceled.
// In degraded mode it never blocks: unlimited concurrency is allowed.
func (s *DynamicWeighted) Acquire(ctx context.Context, weight int) error {
	if weight <= 0 {
		return xerrors.Errorf("acquisition weight must be positive, got %d", weight)
	}
	if s.degraded.Load() {
		return nil
	}

	s.mu.Lock()
	if s.inUse+weight <= s.limit {
		s.inUse += weight
		s.mu.Unlock()
		return nil
	}

	w := dynamicWaiter{weight: weight, ch: make(chan struct{})}
	s.waiters = append(s.waiters, w)
	s.mu.Unlock()

	select {
	case <-w.ch:
		return nil
	case <-ctx.Done():
		s.cancelWaiter(w)
		return ctx.Err()
	}
}

// Release gives back weight slots previously acquired.
// Releasing more than is held is a bookkeeping error: the semaphore degrades
// to unlimited mode and reports the condition, instead of leaking or
// corrupting the quota permanently.
func (s *DynamicWeighted) Release(weight int) {
	if s.degraded.Load() {
		return
	}

	s.mu.Lock()
	if weight > s.inUse {
		s.mu.Unlock()
		s.degrade()
		return
	}

	s.inUse -= weight
	s.wakeWaitersLocked()
	s.mu.Unlock()
}

// Resize changes the concurrency limit. Increasing the limit may immediately
// unblock waiters that fit under the new value; decreasing it only affects
// future acquisitions — slots already held are left to finish naturally.
func (s *DynamicWeighted) Resize(limit int) error {
	if limit < 1 {
		return xerrors.Errorf("concurrency limit must be a positive integer, got %d", limit)
	}

	s.mu.Lock()
	s.limit = limit
	s.wakeWaitersLocked()
	s.mu.Unlock()
	return nil
}

// wakeWaitersLocked grants slots to waiters in FIFO order while they fit.
// Callers must hold s.mu.
func (s *DynamicWeighted) wakeWaitersLocked() {
	granted := 0
	for granted < len(s.waiters) {
		w := s.waiters[granted]
		// FIFO: do not skip a heavy request in favor of a lighter one,
		// otherwise scheduling order would drift between runs.
		if s.inUse+w.weight > s.limit {
			break
		}
		s.inUse += w.weight
		close(w.ch)
		granted++
	}
	s.waiters = s.waiters[granted:]
}

// cancelWaiter removes a waiter whose context ended while it was blocked.
func (s *DynamicWeighted) cancelWaiter(target dynamicWaiter) {
	s.mu.Lock()
	for i, w := range s.waiters {
		if w == target {
			s.waiters = append(s.waiters[:i], s.waiters[i+1:]...)
			break
		}
	}
	// Cancellation changes nothing about free slots, but a later resize may
	// now fit waiters that were queued behind the canceled one.
	s.wakeWaitersLocked()
	s.mu.Unlock()
}

// degrade switches to unlimited mode. In-flight slots are left untouched;
// from this point on Acquire never blocks and Release is a no-op.
func (s *DynamicWeighted) degrade() {
	if s.degraded.CompareAndSwap(false, true) {
		s.mu.Lock()
		for _, w := range s.waiters {
			close(w.ch)
		}
		s.waiters = nil
		s.mu.Unlock()
	}
}

// Degraded reports whether the semaphore gave up on quota enforcement.
func (s *DynamicWeighted) Degraded() bool {
	return s.degraded.Load()
}

// Limit returns the currently configured concurrency limit.
func (s *DynamicWeighted) Limit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limit
}

// InUse returns the number of slots currently held.
func (s *DynamicWeighted) InUse() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inUse
}

// TryAcquire attempts to take weight slots without blocking.
// It returns true on success. It is mainly useful for tests and diagnostics.
func (s *DynamicWeighted) TryAcquire(weight int) bool {
	if s.degraded.Load() {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inUse+weight <= s.limit {
		s.inUse += weight
		return true
	}
	return false
}
