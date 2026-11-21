package store

import (
	"fmt"

	"golang.org/x/xerrors"
)

// Exit codes used when the vulnerability database store cannot serve a scan
// or cannot honour a requested operation. They are deliberately distinct from
// the generic failure code (1) so that automation can tell the three
// operational situations apart.
const (
	// ExitUnavailable is returned when no integrity-verified version of the
	// database is available locally.
	ExitUnavailable = 10
	// ExitVersionMismatch is returned when a requested or required version is
	// not present locally (for example a pinned version or a delta base).
	ExitVersionMismatch = 11
	// ExitRollbackFailed is returned when the requested rollback target has
	// been evicted or does not verify.
	ExitRollbackFailed = 12
)

// Kind classifies a store failure.
type Kind string

const (
	// KindUnavailable means no usable database version exists.
	KindUnavailable Kind = "unavailable"
	// KindVersionMismatch means the version asked for is not the one present.
	KindVersionMismatch Kind = "version_mismatch"
	// KindRollbackFailed means the rollback could not be performed.
	KindRollbackFailed Kind = "rollback_failed"
	// KindIntegrity means the on-disk or transferred data failed verification.
	KindIntegrity Kind = "integrity"
	// KindInterrupted means the operation was interrupted before completion.
	KindInterrupted Kind = "interrupted"
	// KindInvalid means the input was malformed.
	KindInvalid Kind = "invalid"
)

// Error is a store failure carrying a machine-readable kind and, where
// relevant, the version identifiers needed to reconcile the problem.
type Error struct {
	Kind Kind   `json:"kind"`
	Msg  string `json:"message"`

	Version  string `json:"version,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`

	Err error `json:"-"`
}

func (e *Error) Error() string {
	msg := e.Msg
	if msg == "" && e.Err != nil {
		msg = e.Err.Error()
	}
	if e.Version != "" {
		msg = fmt.Sprintf("%s (version %q)", msg, e.Version)
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// ExitCode implements the interface recognised by cmd/trivy/main.go.
func (e *Error) ExitCode() int {
	switch e.Kind {
	case KindUnavailable, KindIntegrity, KindInterrupted:
		return ExitUnavailable
	case KindVersionMismatch:
		return ExitVersionMismatch
	case KindRollbackFailed:
		return ExitRollbackFailed
	default:
		return 1
	}
}

func unavailable(format string, args ...any) *Error {
	return &Error{Kind: KindUnavailable, Msg: fmt.Sprintf(format, args...)}
}

func versionMismatch(format string, args ...any) *Error {
	return &Error{Kind: KindVersionMismatch, Msg: fmt.Sprintf(format, args...)}
}

func rollbackFailed(format string, args ...any) *Error {
	return &Error{Kind: KindRollbackFailed, Msg: fmt.Sprintf(format, args...)}
}

func integrityError(expected, actual string, format string, args ...any) *Error {
	return &Error{
		Kind:     KindIntegrity,
		Msg:      fmt.Sprintf(format, args...),
		Expected: expected,
		Actual:   actual,
	}
}

func invalid(format string, args ...any) *Error {
	return &Error{Kind: KindInvalid, Msg: fmt.Sprintf(format, args...)}
}

func wrapKind(kind Kind, err error, format string, args ...any) *Error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...), Err: err}
}

// IsKind reports whether err is a store error of the given kind.
func IsKind(err error, kind Kind) bool {
	var e *Error
	return xerrors.As(err, &e) && e.Kind == kind
}

// Unavailable returns an error indicating that no usable database version is
// available locally.
func Unavailable(format string, args ...any) *Error {
	return unavailable(format, args...)
}

// VersionMismatch returns an error indicating that the requested version is not
// present locally.
func VersionMismatch(format string, args ...any) *Error {
	return versionMismatch(format, args...)
}

// RollbackFailed returns an error indicating that a rollback cannot be
// performed.
func RollbackFailed(format string, args ...any) *Error {
	return rollbackFailed(format, args...)
}
