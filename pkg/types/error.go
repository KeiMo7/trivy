package types

import (
	"fmt"
)

// ExitError represents an error with a user-friendly message.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

// ExitCoder is implemented by errors that carry a specific process exit code.
// cmd/trivy checks for it so that operational failures (for example, an
// unusable vulnerability database) can be distinguished by automation.
type ExitCoder interface {
	error
	ExitCode() int
}

// ExitCode returns the process exit code carried by the error.
func (e *ExitError) ExitCode() int { return e.Code }

var _ ExitCoder = (*ExitError)(nil)

// UserError represents an error with a user-friendly message.
type UserError struct {
	Message string
}

func (e *UserError) Error() string {
	return e.Message
}
