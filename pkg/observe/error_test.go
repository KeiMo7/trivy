package observe

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestWrapError_StructuredCategories(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantCat ErrorCategory
		wantOp  string
		wantCtx map[string]string
	}{
		{
			name:    "network failure",
			err:     xerrors.New("dial tcp: lookup registry.example.com: no such host"),
			wantCat: CategoryNetwork,
			wantOp:  "inspect",
		},
		{
			name:    "auth failure",
			err:     xerrors.New("401 Unauthorized: authentication required"),
			wantCat: CategoryAuth,
			wantOp:  "pull",
		},
		{
			name:    "missing daemon",
			err:     xerrors.New("cannot connect to the Docker daemon at unix:///var/run/docker.sock"),
			wantCat: CategoryDependency,
			wantOp:  "init",
		},
		{
			name:    "resource limit",
			err:     xerrors.New("image size exceeds maximum allowed size 10GB"),
			wantCat: CategoryResource,
			wantOp:  "inspect",
		},
		{
			name:    "validation",
			err:     xerrors.New("no image sources supplied"),
			wantCat: CategoryValidation,
			wantOp:  "init",
		},
		{
			name:    "user error",
			err:     &types.UserError{Message: "bad input"},
			wantCat: CategoryValidation,
			wantOp:  "validate",
		},
		{
			name:    "unknown error stays internal",
			err:     xerrors.New("something odd happened"),
			wantCat: CategoryInternal,
			wantOp:  "scan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WrapError(tt.wantOp, "/secret/path", tt.err, map[string]string{
				"empty": "",
				"key":   "value",
			})
			require.Error(t, err)

			se, ok := AsScanError(err)
			require.True(t, ok, "failure must be a structured ScanError")
			assert.Equal(t, tt.wantCat, se.Category)
			assert.Equal(t, tt.wantOp, se.Operation)
			assert.Equal(t, "path", se.Target, "absolute paths must be reduced to basename")
			assert.NotContains(t, se.Target, "secret")
			assert.Equal(t, "value", se.Context["key"])
			assert.NotContains(t, se.Context, "empty", "empty context values are dropped")

			// The original cause stays reachable for errors.Is/As.
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

func TestWrapError_CancellationDistinct(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := WrapError("scan", "alpine:3.19", ctx.Err(), nil)
	require.Error(t, err)

	var canceled *CanceledError
	require.True(t, errors.As(err, &canceled), "cancellation must surface as CanceledError, not ScanError")
	assert.Equal(t, "scan", canceled.Operation)
	assert.True(t, IsCanceled(err))
	assert.True(t, errors.Is(err, context.Canceled), "CanceledError must match context.Canceled")

	_, isScanErr := AsScanError(err)
	assert.False(t, isScanErr, "cancellation must not be classified as a failure")
}

func TestWrapError_Nil(t *testing.T) {
	assert.NoError(t, WrapError("op", "target", nil, nil))
}

func TestSanitizeTarget(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "url with credentials",
			in:   "https://user:pass@registry.example.com/image:tag",
			want: "https://registry.example.com/image:tag",
		},
		{
			name: "absolute path reduced to basename",
			in:   "/home/alice/work/project",
			want: "project",
		},
		{
			name: "relative path unchanged",
			in:   "project/Dockerfile",
			want: "project/Dockerfile",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SanitizeTarget(tt.in))
		})
	}
}

func TestNewDependencyError_Understandable(t *testing.T) {
	err := NewDependencyError("docker", "daemon socket not found", "20.10.0")

	se, ok := AsScanError(err)
	require.True(t, ok)
	assert.Equal(t, CategoryDependency, se.Category)
	assert.Equal(t, "docker", se.Context["tool"])
	assert.Equal(t, "20.10.0", se.Context["min_version"])
	assert.Contains(t, err.Error(), "required tool is unavailable: docker")
	assert.NotContains(t, err.Error(), "nil pointer")
}

func TestRun_CanceledVersusFailure(t *testing.T) {
	t.Run("success logs and finishes tracker", func(t *testing.T) {
		var finished bool
		tracker := NewTracker(Options{
			Callback: func(p Progress) {
				if p.Current == 3 {
					finished = true
				}
			},
		})
		ctx := WithTracker(t.Context(), tracker)

		err := Run(ctx, "op", "target", func(ctx context.Context) error {
			tracker.SetTotal(StageScan, 3)
			tracker.Add(3)
			return nil
		})
		require.NoError(t, err)
		assert.True(t, finished)
	})

	t.Run("canceled returns CanceledError", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		ctx = WithTracker(ctx, NewTracker(Options{Callback: func(Progress) {}}))
		err := Run(ctx, "op", "target", func(ctx context.Context) error {
			return ctx.Err()
		})
		var canceled *CanceledError
		require.ErrorAs(t, err, &canceled)
		assert.True(t, IsCanceled(err))
	})

	t.Run("failure returns ScanError", func(t *testing.T) {
		tracker := NewTracker(Options{Callback: func(Progress) {}})
		ctx := WithTracker(t.Context(), tracker)
		err := Run(ctx, "op", "target", func(ctx context.Context) error {
			return xerrors.New("dial tcp: connection refused")
		})
		se, ok := AsScanError(err)
		require.True(t, ok)
		assert.Equal(t, CategoryNetwork, se.Category)
	})

	t.Run("no tracker means fully transparent passthrough", func(t *testing.T) {
		original := xerrors.New("legacy error: keep me")
		err := Run(t.Context(), "op", "target", func(ctx context.Context) error {
			return original
		})
		assert.Same(t, original, err, "default path must return the exact original error")

		assert.NoError(t, Run(t.Context(), "op", "target", func(context.Context) error {
			return nil
		}))
	})
}
