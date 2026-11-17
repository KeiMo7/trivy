package artifact

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/observe"
	"github.com/aquasecurity/trivy/pkg/scan"
)

// failingInitializeService mimics a scanner setup that fails because an
// external tool is unavailable.
func failingInitializeService(context.Context, ScannerConfig) (scan.Service, func(), error) {
	return scan.Service{}, nil, xerrors.New("cannot connect to the Docker daemon at unix:///var/run/docker.sock")
}

// TestRunner_StructuredErrorOnFailure is the acceptance test for a
// deliberately failing input: with observability enabled the caller receives a
// classified ScanError carrying operation and sanitized context rather than a
// raw multi-line output blob.
func TestRunner_StructuredErrorOnFailure(t *testing.T) {
	r := &runner{
		initializeScanService: failingInitializeService,
		progressCallback:      func(observe.Progress) {},
	}

	opts := flag.Options{}
	opts.ObserveOptions = flag.ObserveOptions{Enabled: true}

	_, err := r.scan(t.Context(), opts, failingInitializeService)
	require.Error(t, err)

	se, ok := observe.AsScanError(err)
	require.True(t, ok, "enabled observability must return a structured ScanError")
	assert.Equal(t, observe.CategoryDependency, se.Category)
	assert.Equal(t, "init_service", se.Operation)
	assert.Contains(t, err.Error(), "docker")
	assert.False(t, observe.IsCanceled(err), "a failure must not be reported as canceled")
}

// TestRunner_DefaultPathKeepsLegacyError proves that without the opt-in flag
// the error type and message stay exactly as before.
func TestRunner_DefaultPathKeepsLegacyError(t *testing.T) {
	r := &runner{
		initializeScanService: failingInitializeService,
	}

	opts := flag.Options{} // ObserveOptions.Enabled defaults to false

	_, err := r.scan(t.Context(), opts, failingInitializeService)
	require.Error(t, err)

	var se *observe.ScanError
	assert.False(t, errors.As(err, &se), "default path must not wrap into ScanError")
	var canceled *observe.CanceledError
	assert.False(t, errors.As(err, &canceled))
	assert.Contains(t, err.Error(), "unable to initialize a scan service")
}
