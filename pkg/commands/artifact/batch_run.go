package artifact

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/semaphore"
	"github.com/aquasecurity/trivy/pkg/types"
)

// BatchConfig configures a batch run. It is the library-facing entry point;
// the CLI builds it from flag.BatchOptions.
type BatchConfig struct {
	// Images are the references to scan, in submission order. The order is
	// preserved in the results even though execution is concurrent.
	Images []string

	// Concurrency is the initial maximum number of simultaneous scans.
	Concurrency int

	// MaxConcurrency is the hard ceiling accepted by Resize. 0 disables it.
	MaxConcurrency int

	// PerImageTimeout abandons a scan that runs longer than this. 0 disables
	// the per-image timeout.
	PerImageTimeout time.Duration

	// ResultsDir, when non-empty, receives one report file per image plus a
	// batch summary file. When empty, reports stay in memory only.
	ResultsDir string
}

// scanJob is one unit of work: an image at its submission index.
type scanJob struct {
	index int
	image string
}

// NewBatchRunner constructs a batch runner over an existing Runner. The Runner
// is shared across images — DB initialization, WASM modules and the HTTP
// transport happen exactly once, the same as a single scan.
func NewBatchRunner(r Runner, cfg BatchConfig) (*BatchRunner, error) {
	if err := validateBatchOptions(cfg.Concurrency, cfg.MaxConcurrency, cfg.PerImageTimeout); err != nil {
		return nil, err
	}
	if len(cfg.Images) == 0 {
		return nil, xerrors.New("batch contains no images; pass image arguments or --batch-file")
	}
	sem, err := semaphore.NewDynamic(cfg.Concurrency)
	if err != nil {
		return nil, err
	}
	pool := defaultPoolSize
	if cfg.MaxConcurrency > 0 {
		pool = cfg.MaxConcurrency
	}
	// Never run fewer workers than the initial limit, otherwise the limit
	// could not be reached even before a resize.
	if pool < cfg.Concurrency {
		pool = cfg.Concurrency
	}

	return &BatchRunner{
		runner:         r,
		sem:            sem,
		progress:       newProgressState(len(cfg.Images), cfg.Concurrency),
		imageList:      cfg.Images,
		maxConcurrency: cfg.MaxConcurrency,
		pool:           pool,
		imageTimeout:   cfg.PerImageTimeout,
		resultsDir:     cfg.ResultsDir,
		resizeCh:       make(chan int, 8),
		now:            time.Now,
	}, nil
}

// Run executes the whole batch and returns the aggregated summary. It blocks
// until every image has a conclusion (success, failure, timeout or skip).
// A single image's failure never aborts the batch; only ctx cancellation
// (e.g. SIGINT) stops dispatching new images, while in-flight ones finish.
func (b *BatchRunner) Run(ctx context.Context, baseOpts flag.Options) (Summary, error) {
	startedAt := b.now()

	if b.resultsDir != "" {
		if err := os.MkdirAll(b.resultsDir, 0o755); err != nil {
			return Summary{}, xerrors.Errorf("create batch results directory: %w", err)
		}
	}

	// The job channel is intentionally unbuffered: a job is handed to a
	// worker only when that worker is ready to acquire a concurrency slot.
	// This keeps the number of "claimed" jobs bounded by the worker pool and,
	// crucially, leaves not-yet-dispatched jobs visible to cancellation instead
	// of having them silently parked inside a buffer.
	jobs := make(chan scanJob)
	var wg sync.WaitGroup

	// One feeder goroutine hands jobs out in submission order. Workers pull
	// from the same channel, so scheduling is FIFO under the semaphore.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)
		for i, img := range b.imageList {
			select {
			case jobs <- scanJob{index: i, image: img}:
			case <-ctx.Done():
				// Mark everything not yet dispatched as skipped so the batch
				// still concludes for every requested image.
				b.markSkippedFrom(i)
				return
			}
		}
	}()

	// Resize requests are applied asynchronously so a running batch can react
	// to a new limit without restarting.
	stopResize := b.serveResizes()
	defer stopResize()

	// The pool is sized to the concurrency ceiling, not to the batch size:
	// extra workers park on the semaphore, so resize-up takes effect without
	// spawning goroutines mid-flight and the number of jobs claimed at once
	// stays bounded by the ceiling.
	for w := 0; w < b.poolSize(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				b.processImage(ctx, job, baseOpts)
			}
		}()
	}
	wg.Wait()

	summary := b.progress.summary(b.sem.Limit(), b.sem.Degraded(), startedAt)
	if b.sem.Degraded() {
		// The quota counter failed: warn loudly and keep going unlimited,
		// rather than freezing the main flow on a dead semaphore.
		log.Error("Concurrency accounting entered degraded mode; the batch continued without enforcing the concurrency limit")
		summary.Degraded = true
	}

	if b.resultsDir != "" {
		if err := b.writeSummaryFile(summary); err != nil {
			return summary, xerrors.Errorf("write batch summary: %w", err)
		}
	}
	return summary, nil
}

// poolSize returns the number of worker goroutines to spawn. It is bounded by
// the configured ceiling so a resize-up never needs more workers than the
// ceiling allows; when the ceiling is disabled (0), the pool is capped to keep
// goroutine count sane for very large batches.
func (b *BatchRunner) poolSize() int {
	switch {
	case b.pool > 0:
		return b.pool
	case b.maxConcurrency > 0:
		return b.maxConcurrency
	default:
		// No ceiling configured: allow at most a fixed pool, since workers
		// blocked on the semaphore are cheap but not free.
		return defaultPoolSize
	}
}

// processImage runs the full single-image pipeline for one job under the
// semaphore, with a per-image timeout. Every exit path releases the slot.
func (b *BatchRunner) processImage(parent context.Context, job scanJob, baseOpts flag.Options) {
	ctx := parent
	var cancel context.CancelFunc
	if b.imageTimeout > 0 {
		ctx, cancel = context.WithTimeout(parent, b.imageTimeout)
	} else {
		ctx, cancel = context.WithCancel(parent)
	}
	defer cancel()

	// Acquire outside the timer: queueing time is not billed against the
	// per-image timeout, otherwise a long queue would spuriously time out.
	if err := b.sem.Acquire(parent, 1); err != nil {
		// Only parent cancellation can fail here. The image never ran.
		b.progress.finish(job.index, ImageResult{
			Image:  job.image,
			Status: StatusSkipped,
			Stage:  StageValidate,
			Error:  fmt.Sprintf("batch canceled before start: %v", err),
		})
		return
	}

	// A job may have been waiting for a slot while the batch was canceled.
	// Re-check before doing any work: such an image is reported as skipped,
	// not scanned, and the freshly acquired slot is returned immediately.
	if parent.Err() != nil {
		b.sem.Release(1)
		b.progress.finish(job.index, ImageResult{
			Image:  job.image,
			Status: StatusSkipped,
			Stage:  StageValidate,
			Error:  fmt.Sprintf("batch canceled before start: %v", parent.Err()),
		})
		return
	}

	b.progress.start(job.index, job.image)
	start := b.now()

	// Release is deferred on every path: normal return, panic recovery and
	// timeout all give the slot back. A leaked slot would shrink the pool
	// permanently; the deferred release makes that structurally impossible.
	defer func() {
		if r := recover(); r != nil {
			b.recordError(job, StageScan, xerrors.Errorf("panic recovered: %v", r), start)
		}
		b.sem.Release(1)
	}()

	res := b.scanOne(ctx, job, baseOpts)
	res.Duration = b.now().Sub(start)
	b.progress.finish(job.index, res)
}

// scanOne mirrors the single-image pipeline (ScanImage -> Filter -> Report)
// but maps every failure to a stage-specific ImageResult instead of aborting.
func (b *BatchRunner) scanOne(ctx context.Context, job scanJob, baseOpts flag.Options) ImageResult {
	image := job.image
	opts := baseOpts
	opts.Target = image
	// Per-image output is redirected when a results directory is used, so two
	// images never write to the same --output file concurrently. The submission
	// index guarantees a unique file name even for references that flatten to
	// the same safe string.
	reportPath := ""
	if b.resultsDir != "" {
		reportPath = filepath.Join(b.resultsDir, fmt.Sprintf("%04d-%s.json", job.index, safeFileName(image)))
		opts.Output = reportPath
		// JSON gives a machine-readable per-image artifact; the human-facing
		// conclusion lives in the summary.
		opts.Format = types.FormatJSON
	}

	report, err := b.runner.ScanImage(ctx, opts)
	if err != nil {
		return b.mapError(image, StageScan, err, "")
	}

	report, err = b.runner.Filter(ctx, opts, report)
	if err != nil {
		return b.mapError(image, StageFilter, err, "")
	}

	if err = b.runner.Report(ctx, opts, report); err != nil {
		// The report file may have been partially created, so keep its path.
		return b.mapError(image, StageReport, err, reportPath)
	}

	return ImageResult{
		Image:      image,
		Status:     StatusSuccess,
		Report:     &report,
		ReportPath: reportPath,
	}
}

// mapError translates pipeline errors, distinguishing timeouts so operators
// can tell an abandoned scan from a hard failure.
func (b *BatchRunner) mapError(image, stage string, err error, reportPath string) ImageResult {
	status := StatusFailed
	if isTimeout(err) {
		status = StatusTimeout
	}
	return ImageResult{
		Image:      image,
		Status:     status,
		Stage:      stage,
		Error:      err.Error(),
		ReportPath: reportPath,
	}
}

func (b *BatchRunner) recordError(job scanJob, stage string, err error, start time.Time) {
	b.progress.finish(job.index, ImageResult{
		Image:    job.image,
		Status:   StatusFailed,
		Stage:    stage,
		Error:    err.Error(),
		Duration: b.now().Sub(start),
	})
}

// Resize changes the concurrency limit of a running batch. The new value is
// validated against the configured ceiling and applied asynchronously:
// in-flight scans finish naturally, only newly dispatched scans obey it.
func (b *BatchRunner) Resize(limit int) error {
	if limit < 1 {
		return xerrors.Errorf("batch concurrency must be a positive integer, got %d", limit)
	}
	if b.maxConcurrency > 0 && limit > b.maxConcurrency {
		return xerrors.Errorf("requested concurrency %d exceeds the configured ceiling %d",
			limit, b.maxConcurrency)
	}
	select {
	case b.resizeCh <- limit:
		return nil
	default:
		// The resize channel is buffered and drained continuously; a full
		// channel means resize requests are queued ahead. Surface it rather
		// than silently dropping the operator's request.
		return xerrors.New("a concurrency resize is already pending; retry shortly")
	}
}

// serveResizes applies queued limit changes on a dedicated goroutine. The
// returned stop function closes the loop and is safe to call exactly once,
// when Run has finished dispatching work; it does not depend on the caller's
// context being canceled, so it cannot hang a normal batch completion.
func (b *BatchRunner) serveResizes() func() {
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case limit := <-b.resizeCh:
				if err := b.sem.Resize(limit); err != nil {
					log.Error("Failed to resize batch concurrency", log.Err(err))
					continue
				}
				b.progress.setLimit(limit)
				log.Info("Batch concurrency limit updated", log.Int("limit", limit))
			}
		}
	}()
	return func() { close(done) }
}

// Progress returns a point-in-time snapshot of the batch.
func (b *BatchRunner) Progress() Progress {
	return b.progress.Snapshot()
}

// markSkippedFrom marks every image at index >= start as skipped. Used when
// the batch context ends before the feeder could dispatch all jobs.
func (b *BatchRunner) markSkippedFrom(start int) {
	b.progress.mu.Lock()
	defer b.progress.mu.Unlock()
	for i := start; i < b.progress.total; i++ {
		if b.progress.finished[i] {
			continue
		}
		img := b.imageList[i]
		b.progress.finished[i] = true
		b.progress.results[i] = ImageResult{
			Image:      img,
			Status:     StatusSkipped,
			Stage:      StageValidate,
			Error:      "not started: batch context canceled",
			StartedAt:  b.now(),
			FinishedAt: b.now(),
		}
		b.progress.completed++
	}
}

// writeSummaryFile persists the batch summary next to the per-image reports.
func (b *BatchRunner) writeSummaryFile(s Summary) error {
	path := filepath.Join(b.resultsDir, "batch-summary.json")
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return xerrors.Errorf("marshal summary: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return xerrors.Errorf("write %s: %w", path, err)
	}
	return nil
}

// isTimeout reports whether an error chain contains a deadline cancellation.
func isTimeout(err error) bool {
	return xerrors.Is(err, context.DeadlineExceeded)
}

// unsafeFileNameChars covers path separators and characters illegal on common
// filesystems; image references are flattened into a single file name.
var unsafeFileNameChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func safeFileName(image string) string {
	name := unsafeFileNameChars.ReplaceAllString(image, "_")
	name = strings.Trim(name, "._")
	if name == "" {
		name = "image"
	}
	return name
}
