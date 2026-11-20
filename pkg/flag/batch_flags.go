package flag

import (
	"os"
	"runtime"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// Batch flag names and config keys. They live in their own "batch." config
// namespace so that they never alter the meaning of existing "scan." options.
var (
	BatchFlag = Flag[bool]{
		Name:          "batch",
		ConfigName:    "batch.enabled",
		Usage:         "scan multiple images in one batch; each image succeeds or fails independently and the batch never stops on a single image error",
		TelemetrySafe: true,
	}
	BatchConcurrencyFlag = Flag[int]{
		Name:       "batch-concurrency",
		ConfigName: "batch.concurrency",
		Default:    4,
		Usage: "maximum number of images scanned at the same time in a batch. " +
			"The limit is adjustable while the batch runs; in-flight scans finish naturally and new scans obey the new limit. " +
			"Must be a positive integer and must not exceed --batch-max-concurrency",
		TelemetrySafe: true,
	}
	BatchMaxConcurrencyFlag = Flag[int]{
		Name:       "batch-max-concurrency",
		ConfigName: "batch.max-concurrency",
		Default:    16,
		Usage: "hard ceiling accepted for --batch-concurrency, used to reject configurations that oversubscribe the machine. " +
			"Defaults to a conservative fixed value; set 0 to disable the ceiling check",
		TelemetrySafe: true,
	}
	BatchTimeoutFlag = Flag[time.Duration]{
		Name:       "batch-image-timeout",
		ConfigName: "batch.image-timeout",
		Default:    0,
		Usage: "per-image timeout in batch mode. A scan that does not finish in time is abandoned, its concurrency slot is returned and the rest of the batch continues. " +
			"0 means no per-image timeout (the global --timeout still applies)",
		TelemetrySafe: true,
	}
	BatchFileFlag = Flag[string]{
		Name:       "batch-file",
		ConfigName: "batch.file",
		Usage:      "path to a text file containing one image reference per line; blank lines and lines starting with '#' are ignored. Image arguments can be passed in addition to this file",
	}
	BatchResultsDirFlag = Flag[string]{
		Name:       "batch-results-dir",
		ConfigName: "batch.results-dir",
		Usage:      "directory where per-image reports and the batch summary are written. One report file per image keeps individual results even when a single --output file cannot hold them",
	}
)

// BatchFlagGroup holds options controlling batch image scanning.
// It is only wired into commands that accept batch mode; single-target
// commands keep their existing flag sets untouched.
type BatchFlagGroup struct {
	Batch           *Flag[bool]
	Concurrency     *Flag[int]
	MaxConcurrency  *Flag[int]
	ImageTimeout    *Flag[time.Duration]
	BatchFile       *Flag[string]
	BatchResultsDir *Flag[string]
}

// BatchOptions is the runtime representation of BatchFlagGroup.
type BatchOptions struct {
	Enabled        bool
	Concurrency    int
	MaxConcurrency int
	ImageTimeout   time.Duration
	BatchFile      string
	ResultsDir     string
}

func NewBatchFlagGroup() *BatchFlagGroup {
	return &BatchFlagGroup{
		Batch:           BatchFlag.Clone(),
		Concurrency:     BatchConcurrencyFlag.Clone(),
		MaxConcurrency:  BatchMaxConcurrencyFlag.Clone(),
		ImageTimeout:    BatchTimeoutFlag.Clone(),
		BatchFile:       BatchFileFlag.Clone(),
		BatchResultsDir: BatchResultsDirFlag.Clone(),
	}
}

func (f *BatchFlagGroup) Name() string {
	return "Batch"
}

func (f *BatchFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Batch,
		f.Concurrency,
		f.MaxConcurrency,
		f.ImageTimeout,
		f.BatchFile,
		f.BatchResultsDir,
	}
}

func (f *BatchFlagGroup) ToOptions(opts *Options) error {
	concurrency := f.Concurrency.Value()
	maxConcurrency := f.MaxConcurrency.Value()
	imageTimeout := f.ImageTimeout.Value()
	batchFile := f.BatchFile.Value()
	resultsDir := f.BatchResultsDir.Value()

	// Validation runs at option-parsing time, before any scan starts, so an
	// invalid configuration is rejected at startup with the offending field
	// named explicitly. A zero/negative concurrency must never fall back to
	// a silent default.
	if f.Batch.IsSet() || f.Concurrency.IsSet() || f.MaxConcurrency.IsSet() ||
		f.ImageTimeout.IsSet() || f.BatchFile.IsSet() || f.BatchResultsDir.IsSet() {
		if concurrency < 1 {
			return xerrors.Errorf("invalid 'batch.concurrency' (--batch-concurrency): must be a positive integer, got %d", concurrency)
		}
		if maxConcurrency < 0 {
			return xerrors.Errorf("invalid 'batch.max-concurrency' (--batch-max-concurrency): must be 0 (disabled) or a positive integer, got %d", maxConcurrency)
		}
		if maxConcurrency > 0 && concurrency > maxConcurrency {
			return xerrors.Errorf(
				"invalid 'batch.concurrency' (--batch-concurrency): %d exceeds the configured machine ceiling 'batch.max-concurrency' (--batch-max-concurrency) of %d; raise the ceiling or lower the concurrency",
				concurrency, maxConcurrency)
		}
		if imageTimeout < 0 {
			return xerrors.Errorf("invalid 'batch.image-timeout' (--batch-image-timeout): must be 0 (disabled) or a positive duration, got %s", imageTimeout)
		}
		if batchFile != "" {
			info, err := os.Stat(batchFile)
			if err != nil {
				return xerrors.Errorf("invalid 'batch.file' (--batch-file): %w", err)
			}
			if info.IsDir() {
				return xerrors.Errorf("invalid 'batch.file' (--batch-file): %s is a directory, expected a file", batchFile)
			}
		}
	}

	// A concurrency above GOMAXPROCS is legal for I/O-bound scans, but worth
	// surfacing: operators usually set the limit to bound memory, not threads.
	if concurrency > runtime.GOMAXPROCS(0) {
		log.Warn("Batch concurrency is higher than GOMAXPROCS; image scans are memory-heavy, so monitor RSS",
			log.Int("concurrency", concurrency), log.Int("gomaxprocs", runtime.GOMAXPROCS(0)))
	}

	opts.BatchOptions = BatchOptions{
		Enabled:        f.Batch.Value(),
		Concurrency:    concurrency,
		MaxConcurrency: maxConcurrency,
		ImageTimeout:   imageTimeout,
		BatchFile:      batchFile,
		ResultsDir:     resultsDir,
	}
	return nil
}
