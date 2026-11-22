package vexgen_test

import (
	"path/filepath"
	"testing"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"
)

// filepathTemp returns a per-test document path inside Go's test temp dir, so
// the file-based VEX source used by the real consumer never writes into a
// working directory.
func filepathTemp(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "openvex.json")
}

func ptr(t time.Time) *time.Time { return &t }

var _ = openvex.StatusNotAffected
