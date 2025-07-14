package errors

import (
	"fmt"
)

// AppError represents an application error with additional context.
type AppError struct {
	Err     error
	Message string
	CVE     string
}

func (e *AppError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Err.Error()
}

// NewCVENotFoundError creates a CVE not found error.
func NewCVENotFoundError(cveID string) *AppError {
	return &AppError{
		Message: fmt.Sprintf("CVE %s not found", cveID),
		CVE:     cveID,
	}
}

// NewServiceError creates a service error.
func NewServiceError(err error, source, cveID string) *AppError {
	return &AppError{
		Err:     err,
		Message: fmt.Sprintf("%s service error: %v", source, err),
		CVE:     cveID,
	}
}