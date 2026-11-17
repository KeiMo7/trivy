package scan_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/observe"
	"github.com/aquasecurity/trivy/pkg/scan"
	tTypes "github.com/aquasecurity/trivy/pkg/types"
)

type mockBackend struct {
	scanErr error
}

func (m mockBackend) Scan(context.Context, string, string, []string, tTypes.ScanOptions) (tTypes.ScanResponse, error) {
	if m.scanErr != nil {
		return tTypes.ScanResponse{}, m.scanErr
	}
	return tTypes.ScanResponse{}, nil
}

type mockArtifact struct {
	inspectErr error
	cleaned    chan struct{}
}

func (m *mockArtifact) Inspect(ctx context.Context) (artifact.Reference, error) {
	if m.inspectErr != nil {
		return artifact.Reference{}, m.inspectErr
	}
	return artifact.Reference{Name: "mock", ID: "sha256:abc"}, nil
}

func (m *mockArtifact) Clean(artifact.Reference) error {
	if m.cleaned != nil {
		close(m.cleaned)
	}
	return nil
}

// TestScanArtifact_CanceledDistinctFromFailure verifies that with observability
// enabled, a context cancellation surfaces as *observe.CanceledError while an
// ordinary failure keeps its original (wrapped) error type.
func TestScanArtifact_CanceledDistinctFromFailure(t *testing.T) {
	opts := tTypes.ScanOptions{
		PkgTypes: []string{"os"},
		Scanners: tTypes.Scanners{tTypes.VulnerabilityScanner},
	}

	t.Run("cancellation during inspect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		tracker := observe.NewTracker(observe.Options{Callback: func(observe.Progress) {}})
		ctx = observe.WithTracker(ctx, tracker)

		s := scan.NewService(
			mockBackend{},
			&mockArtifact{inspectErr: context.Canceled},
		)
		_, err := s.ScanArtifact(ctx, opts)
		require.Error(t, err)

		var canceled *observe.CanceledError
		require.ErrorAs(t, err, &canceled, "caller must see 'canceled', not 'failed'")
		assert.True(t, observe.IsCanceled(err))
		assert.False(t, errors.Is(err, xerrors.New("other")))
	})

	t.Run("ordinary failure is not a cancellation", func(t *testing.T) {
		tracker := observe.NewTracker(observe.Options{Callback: func(observe.Progress) {}})
		ctx := observe.WithTracker(t.Context(), tracker)

		s := scan.NewService(
			mockBackend{scanErr: xerrors.New("dial tcp: connection refused")},
			&mockArtifact{},
		)
		_, err := s.ScanArtifact(ctx, opts)
		require.Error(t, err)
		assert.False(t, observe.IsCanceled(err))

		// Default error wrapping is preserved: the message still reads as a
		// scan failure for callers that only handle plain errors.
		assert.Contains(t, err.Error(), "scan failed")
	})

	t.Run("cleanup always runs, even on cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		tracker := observe.NewTracker(observe.Options{Callback: func(observe.Progress) {}})
		ctx = observe.WithTracker(ctx, tracker)

		cleaned := make(chan struct{})
		s := scan.NewService(
			mockBackend{},
			&mockArtifact{inspectErr: context.Canceled, cleaned: cleaned},
		)
		_, err := s.ScanArtifact(ctx, opts)
		require.Error(t, err)

		select {
		case <-cleaned:
		case <-time.After(time.Second):
			t.Fatal("artifact Clean was not invoked after cancellation")
		}
	})

	t.Run("default path without tracker keeps legacy behavior", func(t *testing.T) {
		s := scan.NewService(
			mockBackend{scanErr: xerrors.New("boom")},
			&mockArtifact{},
		)
		_, err := s.ScanArtifact(t.Context(), opts)
		require.Error(t, err)

		var canceled *observe.CanceledError
		assert.False(t, errors.As(err, &canceled), "no CanceledError without a tracker")
		var se *observe.ScanError
		assert.False(t, errors.As(err, &se), "no structured error without a tracker")
	})
}
