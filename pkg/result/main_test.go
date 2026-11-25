package result_test

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/log"
)

// TestMain replaces the package-level deferred slog handler, which buffers
// records without synchronization, with a thread-safe text handler for the
// whole test binary. The result package emits log records from several
// goroutines during filtering, so the default deferred handler would otherwise
// report a data race under -race.
func TestMain(m *testing.M) {
	log.SetDefault(log.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	os.Exit(m.Run())
}
