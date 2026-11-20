package artifact

import (
	"context"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

// Batch scan stages. They are attached to per-image failures so an error
// states both the image and the phase that failed, e.g.
// "image alpine:3.20 failed at stage scan: ...".
const (
	StageValidate = "validate"
	StageScan     = "scan"
	StageFilter   = "filter"
	StageReport   = "report"
)

// ImageStatus is the per-image outcome of a batch scan.
type ImageStatus string

const (
	// StatusSuccess means the image was scanned, filtered and reported without
	// an infrastructure error. Findings (vulnerabilities etc.) do not turn a
	// scan into a failure — they are reported as usual.
	StatusSuccess ImageStatus = "success"

	// StatusFailed means the image could not be scanned or reported. The error
	// is captured on the result and never aborts the rest of the batch.
	StatusFailed ImageStatus = "failed"

	// StatusTimeout means the per-image timeout fired before the scan finished.
	StatusTimeout ImageStatus = "timeout"

	// StatusSkipped means the image was never started, e.g. the batch context
	// was canceled by a signal.
	StatusSkipped ImageStatus = "skipped"
)

// ImageResult is the conclusion for a single image within a batch.
type ImageResult struct {
	// Image is the requested reference, exactly as provided on the CLI or in
	// the batch file.
	Image string `json:"image"`

	Status ImageStatus `json:"status"`

	// Stage is the phase in which a failure happened; empty on success.
	Stage string `json:"stage,omitempty"`

	// Error is the failure message, empty on success.
	Error string `json:"error,omitempty"`

	// Report holds the scan report for successful images. It is nil for
	// failed/timeout/skipped images and is not serialized into the summary.
	Report *types.Report `json:"-"`

	// ReportPath is the file the per-image report was written to when a
	// results directory is configured.
	ReportPath string `json:"report_path,omitempty"`

	// Duration is the wall-clock time spent scanning this image.
	Duration time.Duration `json:"duration_ns"`

	// StartedAt and FinishedAt bracket the per-image processing interval.
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// Progress is a point-in-time, concurrency-safe snapshot of batch execution.
// It is returned by value, so callers can read it without holding locks.
type Progress struct {
	Total     int      `json:"total"`
	Completed int      `json:"completed"`
	Running   []string `json:"running"`
	Pending   int      `json:"pending"`
	Failed    []string `json:"failed"`
	Succeeded int      `json:"succeeded"`
	Limit     int      `json:"limit"`
}

// Summary is the final batch-wide conclusion. Per-image results and this
// summary are derived from the same state, so their totals always agree.
type Summary struct {
	Total      int           `json:"total"`
	Succeeded  int           `json:"succeeded"`
	Failed     int           `json:"failed"`
	TimedOut   int           `json:"timed_out"`
	Skipped    int           `json:"skipped"`
	Limit      int           `json:"concurrency_limit"`
	Degraded   bool          `json:"concurrency_degraded"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Duration   time.Duration `json:"duration_ns"`

	// Results is ordered by the original submission order, regardless of the
	// order in which concurrent scans happened to finish.
	Results []ImageResult `json:"results"`
}

// FailedImages returns the references of images that did not succeed.
func (s Summary) FailedImages() []string {
	var out []string
	for _, r := range s.Results {
		if r.Status != StatusSuccess {
			out = append(out, r.Image)
		}
	}
	return out
}

// progressState is the mutable, mutex-guarded bookkeeping behind Progress.
type progressState struct {
	mu sync.Mutex

	total     int
	completed int
	succeeded int
	running   map[string]struct{}
	results   []ImageResult // indexed by submission position
	finished  []bool
	limit     int
	degraded  bool
}

func newProgressState(total, limit int) *progressState {
	return &progressState{
		total:    total,
		running:  make(map[string]struct{}),
		results:  make([]ImageResult, total),
		finished: make([]bool, total),
		limit:    limit,
	}
}

func (p *progressState) start(index int, image string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running[image] = struct{}{}
	p.results[index] = ImageResult{Image: image, StartedAt: time.Now()}
}

func (p *progressState) finish(index int, res ImageResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished[index] { // defensive: double-finish must not corrupt counters
		return
	}
	// Preserve the start timestamp recorded by start(); the result passed in
	// only carries the conclusion, so without this every image would appear
	// to have zero-length processing time.
	if existing := p.results[index]; !existing.StartedAt.IsZero() && res.StartedAt.IsZero() {
		res.StartedAt = existing.StartedAt
	}
	p.finished[index] = true
	delete(p.running, res.Image)
	p.completed++
	if res.Status == StatusSuccess {
		p.succeeded++
	}
	res.FinishedAt = time.Now()
	if res.StartedAt.IsZero() {
		res.StartedAt = res.FinishedAt
	}
	p.results[index] = res
}

func (p *progressState) setLimit(limit int) {
	p.mu.Lock()
	p.limit = limit
	p.mu.Unlock()
}

func (p *progressState) markDegraded() {
	p.mu.Lock()
	p.degraded = true
	p.mu.Unlock()
}

// Snapshot returns a copy of the current state safe to use without locks.
func (p *progressState) Snapshot() Progress {
	p.mu.Lock()
	defer p.mu.Unlock()

	running := make([]string, 0, len(p.running))
	for img := range p.running {
		running = append(running, img)
	}
	var failed []string
	for _, r := range p.results {
		if r.Image != "" && r.Status != "" && r.Status != StatusSuccess {
			failed = append(failed, r.Image)
		}
	}
	return Progress{
		Total:     p.total,
		Completed: p.completed,
		Running:   running,
		Pending:   p.total - p.completed - len(p.running),
		Failed:    failed,
		Succeeded: p.succeeded,
		Limit:     p.limit,
	}
}

// summary builds the final Summary from the same per-image state.
func (p *progressState) summary(limit int, degraded bool, startedAt time.Time) Summary {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := Summary{
		Total:      p.total,
		Succeeded:  p.succeeded,
		Limit:      limit,
		Degraded:   degraded,
		StartedAt:  startedAt,
		FinishedAt: time.Now(),
		Results:    make([]ImageResult, len(p.results)),
	}
	copy(s.Results, p.results)
	for _, r := range s.Results {
		switch r.Status {
		case StatusFailed:
			s.Failed++
		case StatusTimeout:
			s.TimedOut++
		case StatusSkipped:
			s.Skipped++
		}
	}
	s.Duration = s.FinishedAt.Sub(startedAt)
	return s
}

// validateBatchOptions performs startup validation that needs no I/O. It backs
// the flag-level checks and is reused by library callers and tests.
func validateBatchOptions(concurrency, maxConcurrency int, imageTimeout time.Duration) error {
	if concurrency < 1 {
		return xerrors.Errorf("batch concurrency must be a positive integer, got %d", concurrency)
	}
	if maxConcurrency < 0 {
		return xerrors.Errorf("batch max concurrency must be 0 (disabled) or positive, got %d", maxConcurrency)
	}
	if maxConcurrency > 0 && concurrency > maxConcurrency {
		return xerrors.Errorf("batch concurrency %d exceeds the configured ceiling %d", concurrency, maxConcurrency)
	}
	if imageTimeout < 0 {
		return xerrors.Errorf("batch per-image timeout must be 0 (disabled) or positive, got %s", imageTimeout)
	}
	return nil
}

// defaultPoolSize bounds the worker pool when no concurrency ceiling is set.
// Workers park on the semaphore when the active limit is lower, so the extra
// goroutines cost almost nothing.
const defaultPoolSize = 32

// BatchRunner runs one scan per image under a shared concurrency limit.
type BatchRunner struct {
	runner Runner

	sem      dynamicSemaphore
	progress *progressState

	imageList      []string
	maxConcurrency int
	// pool is the worker-goroutine count, fixed at construction.
	pool         int
	imageTimeout time.Duration
	resultsDir   string

	// resizeCh carries new limits applied while the batch is running.
	resizeCh chan int

	// now is injectable for tests.
	now func() time.Time
}

// dynamicSemaphore is the subset of *semaphore.DynamicWeighted used by the
// batch runner. Keeping it an interface lets tests inject a counting fake.
type dynamicSemaphore interface {
	Acquire(ctx context.Context, weight int) error
	Release(weight int)
	Resize(limit int) error
	Limit() int
	InUse() int
	Degraded() bool
}
