package observe

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

// ErrorCategory classifies scan failures without forcing callers to parse
// human-readable error strings.
type ErrorCategory string

const (
	// CategoryValidation covers bad user input (unknown flags, bad targets).
	CategoryValidation ErrorCategory = "validation"
	// CategoryDependency covers missing or too-old external tooling
	// (docker/podman daemons, image sources, ...).
	CategoryDependency ErrorCategory = "dependency"
	// CategoryAuth covers registry/daemon authentication and authorization.
	CategoryAuth ErrorCategory = "auth"
	// CategoryNetwork covers timeouts, DNS and connection failures.
	CategoryNetwork ErrorCategory = "network"
	// CategoryResource covers local resource limits (disk, memory, image size).
	CategoryResource ErrorCategory = "resource"
	// CategoryInternal covers everything not matching the buckets above.
	CategoryInternal ErrorCategory = "internal"
)

// ScanError is the structured representation of a scan failure. It implements
// the standard error interface and supports errors.Is/errors.As through Unwrap.
type ScanError struct {
	// Category is the coarse-grained failure class.
	Category ErrorCategory `json:"category"`
	// Operation is the logical step that failed, e.g. "inspect_image".
	Operation string `json:"operation"`
	// Target is the sanitized scan target (image reference, directory, ...).
	Target string `json:"target,omitempty"`
	// Context carries small, redacted key/value pairs relevant to the failure.
	Context map[string]string `json:"context,omitempty"`
	// Cause is the underlying error.
	Cause error `json:"-"`
}

// Error renders a single-line message containing only sanitized fields.
func (e *ScanError) Error() string {
	msg := string(e.Category)
	if e.Operation != "" {
		msg += " (" + e.Operation + ")"
	}
	if e.Target != "" {
		msg += ": " + e.Target
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap exposes the cause so errors.Is keeps working.
func (e *ScanError) Unwrap() error {
	return e.Cause
}

// AsScanError returns the structured error attached to err, if any.
func AsScanError(err error) (*ScanError, bool) {
	var se *ScanError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}

// IsCanceled reports whether err (or anything in its chain) represents an
// explicit caller cancellation rather than a scan failure.
func IsCanceled(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	var ce *CanceledError
	return errors.As(err, &ce)
}

// CanceledError is returned when a scan stops because its context was
// canceled. It is deliberately distinct from ScanError so callers can tell
// "canceled" apart from "failed".
type CanceledError struct {
	Operation string
}

func (e *CanceledError) Error() string {
	if e.Operation == "" {
		return "scan canceled"
	}
	return "scan canceled during " + e.Operation
}

// Is makes every CanceledError match context.Canceled as well, so code written
// against the standard library keeps working.
func (e *CanceledError) Is(target error) bool {
	return target == context.Canceled
}

// WrapError converts an error returned by the scan pipeline into a structured
// ScanError. Cancellation is converted into *CanceledError instead, keeping the
// two outcomes strictly separated.
//
// target is sanitized before being stored; extra context values are stored
// verbatim and must already be safe to log.
func WrapError(operation, target string, err error, extra map[string]string) error {
	if err == nil {
		return nil
	}
	if IsCanceled(err) {
		return &CanceledError{Operation: operation}
	}

	// Preserve an already-structured error: re-classifying would discard the
	// precise inner operation and context. Keep the chain for errors.As.
	if existing, ok := AsScanError(err); ok {
		return existing
	}

	return &ScanError{
		Category:  classify(err),
		Operation: operation,
		Target:    SanitizeTarget(target),
		Context:   lo.OmitBy(extra, func(_, v string) bool { return v == "" }),
		Cause:     err,
	}
}

// classify maps well-known sentinel errors to a category; anything unknown is
// reported as an internal error instead of surfacing a nil/typed panic.
func classify(err error) ErrorCategory {
	var userErr *types.UserError
	if errors.As(err, &userErr) {
		return CategoryValidation
	}

	var se *ScanError
	if errors.As(err, &se) {
		return se.Category
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return CategoryNetwork
	case isNetworkError(err):
		return CategoryNetwork
	case isDependencyError(err):
		return CategoryDependency
	case isAuthError(err):
		return CategoryAuth
	case isResourceError(err):
		return CategoryResource
	case isValidationError(err):
		return CategoryValidation
	default:
		return CategoryInternal
	}
}

// SanitizeTarget removes credentials from URL-like targets and collapses
// absolute paths to a stable, non-identifying form following the existing
// redaction strategy (userinfo stripping, cf. report.sarifTarget).
func SanitizeTarget(target string) string {
	if target == "" {
		return ""
	}
	if u, err := url.Parse(target); err == nil && u.User != nil {
		redacted := *u
		redacted.User = nil
		return redacted.String()
	}
	// Keep only the basename of local paths so absolute home directories do
	// not leak into structured errors.
	if filepath.IsAbs(target) {
		return filepath.Base(filepath.Clean(target))
	}
	return target
}

// NewDependencyError builds an understandable "tool missing or too old" error.
// It replaces what would otherwise surface as an opaque nil-deref or
// attribute-style failure when an external tool is unavailable.
func NewDependencyError(tool, reason string, minVersion string) error {
	msg := "required tool is unavailable: " + tool
	if reason != "" {
		msg += ": " + reason
	}
	if minVersion != "" {
		msg += " (minimum version: " + minVersion + ")"
	}
	return &ScanError{
		Category:  CategoryDependency,
		Operation: "check_dependency",
		Context: map[string]string{
			"tool":        tool,
			"reason":      reason,
			"min_version": minVersion,
			"remediation": "install or upgrade the tool, or choose another --image-source",
		},
		Cause: xerrors.New(msg),
	}
}
