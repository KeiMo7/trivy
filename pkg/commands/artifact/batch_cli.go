package artifact

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/types"
)

// withBatchScanService wires the batch-specific scan-service initializer onto
// the runner options. In standalone mode a single artifact cache is opened for
// the whole batch and reused by every image, because the default bbolt fs cache
// takes an exclusive file lock and cannot be opened concurrently per image.
//
// Client/server mode keeps using the per-call remote initializer: the remote
// cache has no local file lock, so sharing is unnecessary there.
func withBatchScanService(ctx context.Context, opts *flag.Options) RunnerOption {
	if opts.ServerAddr != "" {
		return func(*runner) {} // no-op: remote mode needs no shared local cache
	}

	// Resolve the same cache options a single scan would use, then open it once.
	cacheOpts := opts.CacheOpts()
	sharedCache, cleanupCache, err := cache.New(cacheOpts)
	if err != nil {
		// Return an initializer that surfaces the failure on the first scan
		// instead of crashing construction; NewRunner's normal path reports it.
		return func(r *runner) {
			r.initializeScanService = func(context.Context, ScannerConfig) (scan.Service, func(), error) {
				return scan.Service{}, nil, xerrors.Errorf("unable to initialize shared batch cache: %w", err)
			}
		}
	}

	return func(r *runner) {
		r.initializeScanService = func(ictx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
			// Use the exact artifact construction of the single-image path
			// (registry image vs. local tarball), but build the service over
			// the batch-shared cache. The per-call cleanup only tears down the
			// image artifact; the cache is closed once, after the whole batch.
			var newArtifact newArtifactFunc
			if opts.Input != "" {
				newArtifact = newArchiveImageArtifact(conf)
			} else {
				newArtifact = newContainerImageArtifact(ictx, conf)
			}
			service, cleanupArtifact, err := newLocalServiceWithCache(conf, sharedCache, newArtifact)
			if err != nil {
				return scan.Service{}, nil, err
			}
			return service, cleanupArtifact, nil
		}
		r.closeHooks = append(r.closeHooks, func() error { cleanupCache(); return nil })
	}
}

// LoadBatchImages merges image references from CLI arguments and an optional
// batch file into one deduplicated, order-preserving list.
//
// The file contains one reference per line; blank lines and lines whose first
// non-space character is '#' are ignored. CLI arguments come first so an
// operator can prepend ad-hoc images to a file-backed batch. Duplicate
// references are collapsed to their first occurrence because a batch result is
// addressed by image reference.
func LoadBatchImages(cliArgs []string, batchFile string) ([]string, error) {
	var images []string
	seen := make(map[string]struct{})

	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		if _, ok := seen[ref]; ok {
			return
		}
		seen[ref] = struct{}{}
		images = append(images, ref)
	}

	for _, arg := range cliArgs {
		add(arg)
	}

	if batchFile != "" {
		f, err := os.Open(batchFile)
		if err != nil {
			return nil, xerrors.Errorf("open batch file: %w", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			add(line)
		}
		if err := scanner.Err(); err != nil {
			return nil, xerrors.Errorf("read batch file: %w", err)
		}
	}

	if len(images) == 0 {
		return nil, xerrors.New("batch mode requires at least one image: pass image arguments or a non-empty --batch-file")
	}
	return images, nil
}

// RunBatch is the CLI entry point for batch image scanning. It mirrors Run:
// validation, a single shared Runner (DB/modules initialized once), then the
// concurrent batch, and finally an exit decision based on the summary.
//
// The single-image path never calls this function; its behavior, output and
// exit codes are untouched.
func RunBatch(ctx context.Context, opts flag.Options, targetKind TargetKind) (Summary, error) {
	if targetKind != TargetContainerImage {
		return Summary{}, xerrors.Errorf("batch mode is currently supported for container images only, got %s", targetKind)
	}

	images, err := LoadBatchImages(opts.Args(), opts.BatchFile)
	if err != nil {
		return Summary{}, err
	}

	// A single --output file cannot hold one report per image. Require an
	// explicit results directory so successful images still produce artifacts
	// and failed ones do not silently overwrite each other.
	if opts.Output != "" && opts.ResultsDir == "" {
		return Summary{}, xerrors.New(
			"batch mode needs --batch-results-dir when --output is set: each image gets its own report file; " +
				"a single output file cannot represent multiple images")
	}

	r, err := NewRunner(ctx, opts, targetKind, withBatchScanService(ctx, &opts))
	if err != nil {
		if xerrors.Is(err, SkipScan) {
			return Summary{}, nil
		}
		return Summary{}, xerrors.Errorf("init error: %w", err)
	}
	defer func() {
		if cErr := r.Close(ctx); cErr != nil {
			log.ErrorContext(ctx, "failed to close runner: %s", cErr)
		}
	}()

	br, err := NewBatchRunner(r, BatchConfig{
		Images:          images,
		Concurrency:     opts.Concurrency,
		MaxConcurrency:  opts.MaxConcurrency,
		PerImageTimeout: opts.ImageTimeout,
		ResultsDir:      opts.ResultsDir,
	})
	if err != nil {
		return Summary{}, xerrors.Errorf("batch configuration error: %w", err)
	}

	summary, err := br.Run(ctx, opts)
	if err != nil {
		return summary, xerrors.Errorf("batch run error: %w", err)
	}
	return summary, nil
}

// ExitBatch converts a finished batch into the process exit behavior.
//
// Unlike the single-image command, a batch does not turn per-image scan
// failures into a process error: the batch infrastructure succeeded and every
// image has a recorded conclusion. The existing --exit-code mechanism is still
// honored for images that produced findings, so CI gate behavior is preserved.
func ExitBatch(ctx context.Context, opts flag.Options, summary Summary) error {
	logBatchSummary(ctx, summary)

	if opts.ExitCode != 0 {
		for _, res := range summary.Results {
			if res.Status == StatusSuccess && res.Report != nil && res.Report.Results.Failed() {
				return &types.ExitError{Code: opts.ExitCode}
			}
		}
	}
	return nil
}

// logBatchSummary emits the human-readable, stable batch conclusion to stderr.
func logBatchSummary(ctx context.Context, s Summary) {
	log.InfoContext(ctx, "Batch scan finished",
		log.Int("total", s.Total),
		log.Int("succeeded", s.Succeeded),
		log.Int("failed", s.Failed),
		log.Int("timed_out", s.TimedOut),
		log.Int("skipped", s.Skipped),
		log.Int("concurrency", s.Limit),
		log.String("duration", s.Duration.Round(time.Millisecond).String()),
	)
	for _, res := range s.Results {
		if res.Status == StatusSuccess {
			continue
		}
		log.ErrorContext(ctx, "Image failed",
			log.String("image", res.Image),
			log.String("status", string(res.Status)),
			log.String("stage", res.Stage),
			log.String("error", res.Error),
		)
	}
}
