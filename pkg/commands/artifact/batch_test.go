package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

// fakeRunner is an in-memory Runner used to drive the batch layer without any
// registry, DB or filesystem scanning. Each image maps to a scripted behavior.
type fakeRunner struct {
	mu sync.Mutex

	// behaviors maps image reference to its scripted outcome.
	behaviors map[string]fakeBehavior

	// calls records the order in which ScanImage was invoked.
	calls []string

	// scanDelay is how long each ScanImage blocks, to force real concurrency.
	scanDelay time.Duration

	// active tracks currently running scans, for asserting the live limit.
	active    atomic.Int32
	maxActive atomic.Int32

	// block, when non-nil, makes every ScanImage in blockImages wait until it
	// is closed (or the context ends). Other images pass straight through.
	block       chan struct{}
	blockImages map[string]struct{}
}

type fakeBehavior struct {
	scanErr   error
	filterErr error
	reportErr error
	report    types.Report
}

func newFakeRunner(behaviors map[string]fakeBehavior) *fakeRunner {
	return &fakeRunner{behaviors: behaviors}
}

func (f *fakeRunner) ScanImage(ctx context.Context, opts flag.Options) (types.Report, error) {
	f.mu.Lock()
	f.calls = append(f.calls, opts.Target)
	f.mu.Unlock()

	cur := f.active.Add(1)
	for {
		seen := f.maxActive.Load()
		if cur <= seen || f.maxActive.CompareAndSwap(seen, cur) {
			break
		}
	}
	defer f.active.Add(-1)

	if f.block != nil {
		if _, blocked := f.blockImages[opts.Target]; blocked {
			// Stay blocked but remain responsive to cancellation so a
			// per-image timeout can abandon this scan and unwind cleanly.
			select {
			case <-f.block:
			case <-ctx.Done():
				return types.Report{}, ctx.Err()
			}
		}
	}
	if f.scanDelay > 0 {
		time.Sleep(f.scanDelay)
	}
	b := f.behaviors[opts.Target]
	if b.scanErr != nil {
		return types.Report{}, b.scanErr
	}
	r := b.report
	r.ArtifactName = opts.Target
	return r, nil
}

func (f *fakeRunner) Filter(_ context.Context, _ flag.Options, report types.Report) (types.Report, error) {
	b := f.behaviors[report.ArtifactName]
	if b.filterErr != nil {
		return types.Report{}, b.filterErr
	}
	return report, nil
}

func (f *fakeRunner) Report(_ context.Context, opts flag.Options, report types.Report) error {
	b := f.behaviors[report.ArtifactName]
	if b.reportErr != nil {
		return b.reportErr
	}
	return nil
}

func (f *fakeRunner) ScanFilesystem(context.Context, flag.Options) (types.Report, error) {
	panic("not used")
}
func (f *fakeRunner) ScanRootfs(context.Context, flag.Options) (types.Report, error) {
	panic("not used")
}
func (f *fakeRunner) ScanRepository(context.Context, flag.Options) (types.Report, error) {
	panic("not used")
}
func (f *fakeRunner) ScanSBOM(context.Context, flag.Options) (types.Report, error) {
	panic("not used")
}
func (f *fakeRunner) ScanVM(context.Context, flag.Options) (types.Report, error) {
	panic("not used")
}
func (f *fakeRunner) Close(context.Context) error { return nil }

func TestBatchRunner_RejectsInvalidConfig(t *testing.T) {
	r := newFakeRunner(nil)

	cases := []struct {
		name string
		cfg  BatchConfig
	}{
		{"zero concurrency", BatchConfig{Images: []string{"a"}, Concurrency: 0}},
		{"negative concurrency", BatchConfig{Images: []string{"a"}, Concurrency: -2}},
		{"above ceiling", BatchConfig{Images: []string{"a"}, Concurrency: 8, MaxConcurrency: 4}},
		{"negative ceiling", BatchConfig{Images: []string{"a"}, Concurrency: 2, MaxConcurrency: -1}},
		{"negative timeout", BatchConfig{Images: []string{"a"}, Concurrency: 2, PerImageTimeout: -time.Second}},
		{"no images", BatchConfig{Images: nil, Concurrency: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewBatchRunner(r, tc.cfg)
			assert.Error(t, err, "invalid configuration must be rejected at startup")
		})
	}
}

func TestBatchRunner_NormalBatchAllSucceed(t *testing.T) {
	images := []string{"alpine:3.20", "debian:12", "ubuntu:24.04", "busybox:1.36", "nginx:1.27"}
	behaviors := map[string]fakeBehavior{}
	for _, img := range images {
		behaviors[img] = fakeBehavior{report: types.Report{ArtifactName: img}}
	}
	r := newFakeRunner(behaviors)
	r.scanDelay = 5 * time.Millisecond

	br, err := NewBatchRunner(r, BatchConfig{
		Images:      images,
		Concurrency: 2,
	})
	require.NoError(t, err)

	summary, err := br.Run(context.Background(), flag.Options{})
	require.NoError(t, err)

	assert.Equal(t, len(images), summary.Total)
	assert.Equal(t, len(images), summary.Succeeded)
	assert.Equal(t, 0, summary.Failed+summary.TimedOut+summary.Skipped)
	assert.False(t, summary.Degraded)

	// Submission order is preserved in the results regardless of scheduling.
	for i, img := range images {
		assert.Equal(t, img, summary.Results[i].Image)
		assert.Equal(t, StatusSuccess, summary.Results[i].Status)
		assert.NotNil(t, summary.Results[i].Report)
		assert.False(t, summary.Results[i].StartedAt.IsZero())
		assert.True(t, summary.Results[i].FinishedAt.After(summary.Results[i].StartedAt) ||
			summary.Results[i].FinishedAt.Equal(summary.Results[i].StartedAt),
			"finished_at must not precede started_at")
	}

	// The live concurrency never exceeded the configured limit.
	assert.LessOrEqual(t, r.maxActive.Load(), int32(2))

	// Every image was scanned exactly once.
	assert.Len(t, r.calls, len(images))
}

func TestBatchRunner_SingleImageFailureDoesNotStopBatch(t *testing.T) {
	images := []string{"good-1", "broken-pull", "good-2", "bad-layer", "good-3"}
	behaviors := map[string]fakeBehavior{
		"good-1":      {},
		"good-2":      {},
		"good-3":      {},
		"broken-pull": {scanErr: errors.New("unable to initialize container image: manifest unknown")},
		"bad-layer":   {scanErr: errors.New("layer digest mismatch")},
	}
	r := newFakeRunner(behaviors)
	r.scanDelay = 5 * time.Millisecond

	br, err := NewBatchRunner(r, BatchConfig{Images: images, Concurrency: 3})
	require.NoError(t, err)

	summary, err := br.Run(context.Background(), flag.Options{})
	require.NoError(t, err, "the batch itself must not fail because one image failed")

	assert.Equal(t, 3, summary.Succeeded)
	assert.Equal(t, 2, summary.Failed)
	assert.Equal(t, len(images), summary.Succeeded+summary.Failed, "every image gets a conclusion")

	// Failures identify both the image and the stage, and carry the reason.
	byImage := map[string]ImageResult{}
	for _, res := range summary.Results {
		byImage[res.Image] = res
	}
	failed := byImage["broken-pull"]
	assert.Equal(t, StatusFailed, failed.Status)
	assert.Equal(t, StageScan, failed.Stage)
	assert.Contains(t, failed.Error, "manifest unknown")

	// A filter-stage error is attributed to its own stage.
	behaviors2 := map[string]fakeBehavior{
		"ok":    {},
		"fatal": {filterErr: errors.New("filter boom")},
	}
	r2 := newFakeRunner(behaviors2)
	br2, err := NewBatchRunner(r2, BatchConfig{Images: []string{"ok", "fatal"}, Concurrency: 2})
	require.NoError(t, err)
	s2, err := br2.Run(context.Background(), flag.Options{})
	require.NoError(t, err)
	assert.Equal(t, StageFilter, s2.Results[1].Stage)
}

// TestBatchRunner_FailureDoesNotDelayOthers is the acceptance assertion:
// one image failing must not extend the completion time of the others.
func TestBatchRunner_FailureDoesNotDelayOthers(t *testing.T) {
	images := []string{"slow-bad", "fast-1", "fast-2", "fast-3"}
	behaviors := map[string]fakeBehavior{
		"slow-bad": {scanErr: errors.New("pull timeout")},
		"fast-1":   {},
		"fast-2":   {},
		"fast-3":   {},
	}
	r := newFakeRunner(behaviors)
	// The failing image would block for a long time if the batch waited on it
	// synchronously; the fast ones must finish around their own short delay.
	r.scanDelay = 0
	r.block = make(chan struct{})
	r.blockImages = map[string]struct{}{"slow-bad": {}}

	br, err := NewBatchRunner(r, BatchConfig{Images: images, Concurrency: 4})
	require.NoError(t, err)

	done := make(chan Summary, 1)
	go func() {
		s, _ := br.Run(context.Background(), flag.Options{})
		done <- s
	}()

	// Let the fast images complete while slow-bad stays blocked, then release
	// the failure. The others are already done and are not held back.
	require.Eventually(t, func() bool {
		p := br.Progress()
		// Progress must be observable while the batch is still running:
		// total is fixed, three fast scans complete, the bad one stays running.
		return p.Total == len(images) && p.Completed == 3 && len(p.Running) == 1
	}, time.Second, 5*time.Millisecond)

	p := br.Progress()
	assert.Equal(t, len(images), p.Total)
	assert.ElementsMatch(t, []string{"slow-bad"}, p.Running)
	assert.Empty(t, p.Failed, "the blocked image has not concluded yet")
	close(r.block)

	select {
	case summary := <-done:
		assert.Equal(t, 3, summary.Succeeded)
		assert.Equal(t, 1, summary.Failed)
		fastFinished := 0
		for _, res := range summary.Results {
			if res.Image == "slow-bad" {
				assert.Equal(t, StatusFailed, res.Status)
				continue
			}
			// The healthy images finished before the blocked failure was
			// released: their duration is bounded by the fast path.
			assert.Equal(t, StatusSuccess, res.Status)
			assert.Less(t, res.Duration, 100*time.Millisecond,
				"image %s must not be delayed by the failing image", res.Image)
			fastFinished++
		}
		assert.Equal(t, 3, fastFinished)
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not finish after the failing image was released")
	}
}

func TestBatchRunner_PerImageTimeoutAbandonsAndContinues(t *testing.T) {
	images := []string{"stuck", "healthy"}
	releaseStuck := make(chan struct{})
	behaviors := map[string]fakeBehavior{
		"stuck":   {}, // blocks on the runner's block channel until timeout
		"healthy": {},
	}
	r := newFakeRunner(behaviors)
	r.block = releaseStuck
	r.blockImages = map[string]struct{}{"stuck": {}}

	br, err := NewBatchRunner(r, BatchConfig{
		Images:          images,
		Concurrency:     2,
		PerImageTimeout: 50 * time.Millisecond,
	})
	require.NoError(t, err)

	summary, err := br.Run(context.Background(), flag.Options{})
	require.NoError(t, err)
	close(releaseStuck) // let the abandoned goroutine unwind; its slot must already be free

	assert.Equal(t, StatusTimeout, summary.Results[0].Status)
	assert.Equal(t, StageScan, summary.Results[0].Stage)
	assert.Equal(t, StatusSuccess, summary.Results[1].Status, "the healthy image must complete despite the timeout")
	assert.Equal(t, 1, summary.TimedOut)
}

func TestBatchRunner_DynamicResize(t *testing.T) {
	const n = 8
	images := make([]string, n)
	behaviors := map[string]fakeBehavior{}
	for i := range images {
		images[i] = fmt.Sprintf("img-%d", i)
		behaviors[images[i]] = fakeBehavior{}
	}
	r := newFakeRunner(behaviors)
	gate := make(chan struct{})
	r.block = gate // all scans block until the test opens the gate
	r.blockImages = map[string]struct{}{}
	for _, img := range images {
		r.blockImages[img] = struct{}{}
	}

	br, err := NewBatchRunner(r, BatchConfig{Images: images, Concurrency: 2, MaxConcurrency: 6})
	require.NoError(t, err)

	done := make(chan Summary, 1)
	go func() {
		s, _ := br.Run(context.Background(), flag.Options{})
		done <- s
	}()

	require.Eventually(t, func() bool { return r.active.Load() == 2 }, time.Second, time.Millisecond)
	assert.Equal(t, int32(2), r.maxActive.Load(), "initial limit of 2 must hold")

	// Resize up: more scans should start up to the new limit.
	require.NoError(t, br.Resize(5))
	require.Eventually(t, func() bool { return r.active.Load() == 5 }, time.Second, time.Millisecond)
	assert.Equal(t, int32(5), r.maxActive.Load())

	// Resize beyond ceiling is rejected and leaves the active limit untouched.
	assert.Error(t, br.Resize(7))
	assert.Equal(t, 5, br.Progress().Limit)

	// Resize down: running scans finish naturally; active count stays at 5
	// until the gate opens, then no new scan exceeds the new limit.
	require.NoError(t, br.Resize(1))
	require.Eventually(t, func() bool { return br.Progress().Limit == 1 }, time.Second, time.Millisecond)
	assert.Equal(t, int32(5), r.active.Load(), "lowering the limit must not preempt running scans")

	close(gate)
	select {
	case summary := <-done:
		assert.Equal(t, n, summary.Succeeded)
		assert.Equal(t, 1, summary.Limit, "the final summary records the last active limit")
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not finish after gate release")
	}
}

// TestBatchRunner_QuotaReturnedAfterPanic is the second acceptance assertion:
// an abnormal exit (panic) inside one scan returns its concurrency slot fully.
func TestBatchRunner_QuotaReturnedAfterPanic(t *testing.T) {
	images := []string{"panicky", "after-1", "after-2", "after-3"}
	behaviors := map[string]fakeBehavior{
		"panicky": {scanErr: errPanic}, // handled specially below via panickingRunner
		"after-1": {},
		"after-2": {},
		"after-3": {},
	}
	pr := &panickingRunner{fakeRunner: newFakeRunner(behaviors)}
	pr.scanDelay = 5 * time.Millisecond

	br, err := NewBatchRunner(pr, BatchConfig{Images: images, Concurrency: 1})
	require.NoError(t, err)

	summary, err := br.Run(context.Background(), flag.Options{})
	require.NoError(t, err)

	assert.Equal(t, StatusFailed, summary.Results[0].Status)
	assert.Equal(t, StageScan, summary.Results[0].Stage)
	assert.Contains(t, summary.Results[0].Error, "panic recovered")
	assert.Equal(t, 3, summary.Succeeded, "images after the panic must still run to success")

	// The single slot was returned on every path: nothing remains in use and
	// the semaphore did not degrade.
	assert.Equal(t, 0, br.sem.InUse())
	assert.False(t, br.sem.Degraded())
}

var errPanic = errors.New("synthetic panic marker")

type panickingRunner struct {
	*fakeRunner
}

func (p *panickingRunner) ScanImage(ctx context.Context, opts flag.Options) (types.Report, error) {
	if opts.Target == "panicky" {
		panic(errPanic)
	}
	return p.fakeRunner.ScanImage(ctx, opts)
}

func TestBatchRunner_ContextCancelMarksRestSkipped(t *testing.T) {
	images := []string{"a", "b", "c", "d"}
	behaviors := map[string]fakeBehavior{}
	for _, img := range images {
		behaviors[img] = fakeBehavior{}
	}
	r := newFakeRunner(behaviors)
	gate := make(chan struct{})
	r.block = gate
	r.blockImages = map[string]struct{}{}
	for _, img := range images {
		r.blockImages[img] = struct{}{}
	}

	br, err := NewBatchRunner(r, BatchConfig{Images: images, Concurrency: 2})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Summary, 1)
	go func() {
		s, _ := br.Run(ctx, flag.Options{})
		done <- s
	}()

	require.Eventually(t, func() bool { return r.active.Load() == 2 }, time.Second, time.Millisecond)
	cancel()

	// Wait until the feeder reacts to cancellation and marks the not-yet-
	// dispatched images as skipped before releasing the two running scans.
	require.Eventually(t, func() bool { return br.Progress().Completed >= 2 }, time.Second, time.Millisecond)
	close(gate) // release the two running scans so the batch can conclude

	select {
	case summary := <-done:
		assert.Equal(t, len(images), summary.Total)

		// Images that never started must be marked skipped, distinct from the
		// two that were already running when cancellation arrived.
		assert.GreaterOrEqual(t, summary.Skipped, 1, "undispatched images must be marked skipped")

		// No image is left without a conclusion, and every non-success is
		// either a canceled in-flight scan or a never-started skip.
		concluded := summary.Succeeded + summary.Failed + summary.TimedOut + summary.Skipped
		assert.Equal(t, summary.Total, concluded)
		for _, rr := range summary.Results {
			assert.NotEmpty(t, rr.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not conclude after cancellation")
	}
}

func TestBatchRunner_SummaryAndProgressNumbersAgree(t *testing.T) {
	images := []string{"ok-1", "fail-1", "ok-2"}
	behaviors := map[string]fakeBehavior{
		"ok-1":   {},
		"ok-2":   {},
		"fail-1": {scanErr: errors.New("boom")},
	}
	r := newFakeRunner(behaviors)
	r.scanDelay = 5 * time.Millisecond

	br, err := NewBatchRunner(r, BatchConfig{Images: images, Concurrency: 2})
	require.NoError(t, err)
	summary, err := br.Run(context.Background(), flag.Options{})
	require.NoError(t, err)

	// The summary counters and the per-image result list must reconcile.
	counts := map[ImageStatus]int{}
	for _, res := range summary.Results {
		counts[res.Status]++
	}
	assert.Equal(t, counts[StatusSuccess], summary.Succeeded)
	assert.Equal(t, counts[StatusFailed], summary.Failed)
	assert.Equal(t, summary.Total, summary.Succeeded+summary.Failed+summary.TimedOut+summary.Skipped)
	assert.ElementsMatch(t, []string{"fail-1"}, summary.FailedImages())

	// Final progress snapshot agrees with the finished summary.
	p := br.Progress()
	assert.Equal(t, summary.Total, p.Total)
	assert.Equal(t, summary.Total, p.Completed)
	assert.Equal(t, summary.Succeeded, p.Succeeded)
	assert.ElementsMatch(t, summary.FailedImages(), p.Failed)
	assert.Empty(t, p.Running)
}

func TestBatchRunner_DeterministicAcrossRuns(t *testing.T) {
	images := []string{"img-a", "img-b", "img-c", "img-d", "img-e", "img-f"}
	behaviors := map[string]fakeBehavior{}
	for _, img := range images {
		behaviors[img] = fakeBehavior{}
	}

	runOnce := func() []ImageResult {
		r := newFakeRunner(behaviors)
		r.scanDelay = 2 * time.Millisecond
		br, err := NewBatchRunner(r, BatchConfig{Images: images, Concurrency: 3})
		require.NoError(t, err)
		s, err := br.Run(context.Background(), flag.Options{})
		require.NoError(t, err)
		return s.Results
	}

	first := runOnce()
	second := runOnce()
	require.Len(t, first, len(images))
	for i := range images {
		// Same image, same conclusion, same submission position every run.
		assert.Equal(t, first[i].Image, second[i].Image)
		assert.Equal(t, first[i].Status, second[i].Status)
		assert.Equal(t, images[i], first[i].Image)
	}
}

// fileWritingRunner behaves like fakeRunner but really writes the per-image
// output file, so results-directory behavior can be asserted end to end.
type fileWritingRunner struct {
	*fakeRunner
	dir string
}

func (r *fileWritingRunner) Report(_ context.Context, opts flag.Options, report types.Report) error {
	if opts.Output != "" {
		if err := os.MkdirAll(filepath.Dir(opts.Output), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(opts.Output, []byte(report.ArtifactName), 0o644); err != nil {
			return err
		}
	}
	return r.fakeRunner.Report(context.Background(), opts, report)
}

func TestBatchRunner_ResultsDirWritesPerImageReportsAndSummary(t *testing.T) {
	images := []string{"reg.example.com/ns/a:1", "reg.example.com/ns/b:1", "broken:1"}
	behaviors := map[string]fakeBehavior{
		"reg.example.com/ns/a:1": {},
		"reg.example.com/ns/b:1": {},
		"broken:1":               {scanErr: errors.New("pull failed")},
	}
	base := newFakeRunner(behaviors)
	r := &fileWritingRunner{fakeRunner: base, dir: ""}

	dir := t.TempDir()
	br, err := NewBatchRunner(r, BatchConfig{
		Images:      images,
		Concurrency: 2,
		ResultsDir:  dir,
	})
	require.NoError(t, err)

	summary, err := br.Run(context.Background(), flag.Options{})
	require.NoError(t, err)

	// One JSON report per successful image, indexed by submission position.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	assert.Contains(t, names, "batch-summary.json")
	assert.Len(t, entries, 3) // 2 per-image reports + 1 summary

	for _, res := range summary.Results {
		if res.Status == StatusSuccess {
			assert.NotEmpty(t, res.ReportPath)
			data, rerr := os.ReadFile(res.ReportPath)
			require.NoError(t, rerr)
			assert.Equal(t, res.Image, string(data))
		} else {
			// A failed image must not claim a report file that was never written.
			assert.Empty(t, res.ReportPath)
		}
	}

	// The summary file on disk matches the returned summary.
	data, err := os.ReadFile(filepath.Join(dir, "batch-summary.json"))
	require.NoError(t, err)
	var onDisk Summary
	require.NoError(t, json.Unmarshal(data, &onDisk))
	assert.Equal(t, summary.Total, onDisk.Total)
	assert.Equal(t, summary.Succeeded, onDisk.Succeeded)
	assert.Equal(t, summary.Failed, onDisk.Failed)
}

func TestSafeFileName(t *testing.T) {
	cases := map[string]string{
		"alpine:3.20":                  "alpine_3.20",
		"reg.example.com/ns/img:tag":   "reg.example.com_ns_img_tag",
		"gcr.io/proj/image@sha256:abc": "gcr.io_proj_image_sha256_abc",
	}
	for in, want := range cases {
		assert.Equal(t, want, safeFileName(in))
	}
}

func TestLoadBatchImages(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	require.NoError(t, os.WriteFile(path, []byte("# header\n\nalpine:3.20\n  busybox:1.36  \n# tail\n"), 0o644))

	got, err := LoadBatchImages([]string{"cli-img:1", "alpine:3.20"}, path)
	require.NoError(t, err)
	// CLI first, comments/blanks ignored, duplicates collapsed, order kept.
	assert.Equal(t, []string{"cli-img:1", "alpine:3.20", "busybox:1.36"}, got)

	_, err = LoadBatchImages(nil, filepath.Join(dir, "missing.txt"))
	assert.Error(t, err)
}

// fakeSemaphore models a DynamicWeighted that has entered degraded mode:
// Acquire never blocks, so the batch runs without a concurrency ceiling.
type fakeSemaphore struct {
	limit    int
	degraded bool
	inUse    atomic.Int32
}

func (s *fakeSemaphore) Acquire(_ context.Context, _ int) error {
	s.inUse.Add(1)
	return nil
}
func (s *fakeSemaphore) Release(_ int)          { s.inUse.Add(-1) }
func (s *fakeSemaphore) Resize(limit int) error { s.limit = limit; return nil }
func (s *fakeSemaphore) Limit() int             { return s.limit }
func (s *fakeSemaphore) InUse() int             { return int(s.inUse.Load()) }
func (s *fakeSemaphore) Degraded() bool         { return s.degraded }

func TestBatchRunner_DegradedSemaphoreRunsUnlimitedAndWarns(t *testing.T) {
	const n = 12
	images := make([]string, n)
	behaviors := map[string]fakeBehavior{}
	for i := range images {
		images[i] = fmt.Sprintf("img-%d", i)
		behaviors[images[i]] = fakeBehavior{}
	}
	r := newFakeRunner(behaviors)
	r.scanDelay = 5 * time.Millisecond

	br, err := NewBatchRunner(r, BatchConfig{Images: images, Concurrency: 2})
	require.NoError(t, err)

	// Simulate the concurrency counter failing before the batch starts: the
	// runner must keep going without a ceiling rather than hang.
	br.sem = &fakeSemaphore{limit: 2, degraded: true}
	br.progress.markDegraded()

	summary, err := br.Run(context.Background(), flag.Options{})
	require.NoError(t, err, "a degraded semaphore must not fail the batch")
	assert.True(t, summary.Degraded, "the summary must surface degraded mode")
	assert.Equal(t, n, summary.Succeeded)
	assert.Greater(t, r.maxActive.Load(), int32(2),
		"degraded mode means the configured limit is no longer enforced")
}
