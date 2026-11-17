package observe

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/log"
)

// Run executes fn with observability enabled. It is a thin wrapper:
//
//   - emits one Info log on entry, one on successful exit and one Error log on
//     failure (cancellation is logged at Info because it is caller-driven);
//   - converts failures into *ScanError and cancellation into *CanceledError;
//   - closes the tracker so the final progress snapshot is always delivered.
//
// When ctx carries no tracker, Run simply calls fn and wraps its error, leaving
// the default behavior unchanged.
func Run(ctx context.Context, operation, target string, fn func(ctx context.Context) error) error {
	tracker := FromContext(ctx)

	if tracker != nil {
		log.InfoContext(ctx, "Scan stage started",
			log.String("operation", operation), log.String("target", SanitizeTarget(target)))
	}

	err := fn(ctx)
	if err != nil {
		if tracker != nil {
			tracker.Finish()
		}
		// Without a tracker the capability is off: stay completely silent and
		// return the original error so the default logging/error behavior is
		// byte-for-byte unchanged.
		if tracker == nil {
			return err
		}
		if IsCanceled(err) {
			log.InfoContext(ctx, "Scan stage canceled",
				log.String("operation", operation))
			return &CanceledError{Operation: operation}
		}
		wrapped := WrapError(operation, target, err, nil)
		log.ErrorContext(ctx, "Scan stage failed",
			log.String("operation", operation),
			log.String("target", SanitizeTarget(target)),
			log.Err(err))
		return wrapped
	}

	if tracker != nil {
		tracker.Finish()
	} else {
		return nil
	}
	log.InfoContext(ctx, "Scan stage completed",
		log.String("operation", operation))
	return nil
}
