package observe

import (
	"log/slog"

	"github.com/aquasecurity/trivy/pkg/log"
)

// NewLogCallback returns a ProgressCallback that renders each snapshot as a
// single structured log line. It is the default sink when observability is
// enabled from the CLI without a programmatic callback.
func NewLogCallback() ProgressCallback {
	return func(p Progress) {
		attrs := []any{
			log.String("stage", string(p.Stage)),
			log.Int64("current", p.Current),
			log.Int64("total", p.Total),
			log.Int64("bytes_processed", p.BytesProcessed),
			log.Duration("elapsed", p.Elapsed),
		}
		if p.Total > 0 {
			attrs = append(attrs, slog.Float64("percent", float64(p.Current)/float64(p.Total)*100))
		}
		log.Info("Scan progress", attrs...)
	}
}
