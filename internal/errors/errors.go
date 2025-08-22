package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// Common errors
var (
	ErrCVENotFound    = errors.New("CVE not found")
	ErrInvalidCVEID   = errors.New("invalid CVE ID format")
	ErrEmptyCVEID     = errors.New("CVE ID is required")
	ErrServiceTimeout = errors.New("service timeout")
	ErrRateLimited    = errors.New("rate limited")
)

// AppError represents an application error with additional context.
type AppError struct {
	Err        error
	Message    string
	StatusCode int
	Source     string
	CVE        string
}

func (e *AppError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Err.Error()
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// HTTPStatusCode returns the appropriate HTTP status code for the error.
func (e *AppError) HTTPStatusCode() int {
	if e.StatusCode != 0 {
		return e.StatusCode
	}
	return http.StatusInternalServerError
}

// NewCVENotFoundError creates a CVE not found error.
func NewCVENotFoundError(cveID string) *AppError {
	return &AppError{
		Err:        ErrCVENotFound,
		Message:    fmt.Sprintf("CVE %s not found in any available database", cveID),
		StatusCode: http.StatusNotFound,
		CVE:        cveID,
	}
}

// NewInvalidCVEError creates an invalid CVE ID error.
func NewInvalidCVEError(cveID string) *AppError {
	return &AppError{
		Err:        ErrInvalidCVEID,
		Message:    fmt.Sprintf("invalid CVE ID format: %s", cveID),
		StatusCode: http.StatusBadRequest,
		CVE:        cveID,
	}
}

// NewServiceError creates a service error with source information.
func NewServiceError(err error, source, cveID string) *AppError {
	return &AppError{
		Err:        err,
		Message:    fmt.Sprintf("%s service error for %s: %v", source, cveID, err),
		StatusCode: http.StatusServiceUnavailable,
		Source:     source,
		CVE:        cveID,
	}
}
