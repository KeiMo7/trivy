package store

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// lockRetry is how often a lock attempt is retried until the context is done.
const lockRetry = 100 * time.Millisecond

// lock is an advisory lock on the store root. Writers take it exclusively for
// the whole install/activate/rollback/GC operation; readers take it shared for
// the lifetime of a scan so that a concurrent GC cannot evict the version
// being read.
type lock struct {
	fl *flock.Flock
}

func newLock(root string) (*lock, error) {
	// The lock file must live outside the versioned directory tree so that it
	// survives even when versions are removed.
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, xerrors.Errorf("failed to create %s: %w", root, err)
	}
	return &lock{fl: flock.New(filepath.Join(root, lockFile))}, nil
}

func (l *lock) exclusive(ctx context.Context) (func(), error) {
	ok, err := l.fl.TryLockContext(ctx, lockRetry)
	if err != nil {
		return nil, xerrors.Errorf("failed to acquire database write lock: %w", err)
	}
	if !ok {
		return nil, xerrors.New("failed to acquire database write lock")
	}
	return func() {
		if err := l.fl.Unlock(); err != nil {
			log.Debug("Failed to release database write lock", log.Err(err))
		}
	}, nil
}

func (l *lock) shared(ctx context.Context) (func(), error) {
	ok, err := l.fl.TryRLockContext(ctx, lockRetry)
	if err != nil {
		return nil, xerrors.Errorf("failed to acquire database read lock: %w", err)
	}
	if !ok {
		return nil, xerrors.New("failed to acquire database read lock")
	}
	return func() {
		if err := l.fl.Unlock(); err != nil {
			log.Debug("Failed to release database read lock", log.Err(err))
		}
	}, nil
}
