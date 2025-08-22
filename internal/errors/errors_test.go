package errors

import (
	"errors"
	"net/http"
	"testing"
)

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		appError *AppError
		want     string
	}{
		{
			name: "message_takes_priority",
			appError: &AppError{
				Err:     errors.New("underlying error"),
				Message: "custom message",
			},
			want: "custom message",
		},
		{
			name: "fallback_to_underlying_error",
			appError: &AppError{
				Err:     errors.New("underlying error"),
				Message: "",
			},
			want: "underlying error",
		},
		{
			name: "empty_message_and_error",
			appError: &AppError{
				Err:     errors.New(""),
				Message: "",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.appError.Error()
			if got != tt.want {
				t.Errorf("AppError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAppError_Unwrap(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	appErr := &AppError{
		Err:     underlyingErr,
		Message: "custom message",
	}

	unwrapped := appErr.Unwrap()
	if unwrapped != underlyingErr {
		t.Errorf("AppError.Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}
}

func TestAppError_HTTPStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		appError   *AppError
		wantStatus int
	}{
		{
			name: "custom_status_code",
			appError: &AppError{
				StatusCode: http.StatusBadRequest,
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "default_status_code",
			appError: &AppError{
				StatusCode: 0,
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "not_found_status_code",
			appError: &AppError{
				StatusCode: http.StatusNotFound,
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.appError.HTTPStatusCode()
			if got != tt.wantStatus {
				t.Errorf("AppError.HTTPStatusCode() = %v, want %v", got, tt.wantStatus)
			}
		})
	}
}

func TestNewCVENotFoundError(t *testing.T) {
	cveID := "CVE-2023-1234"
	err := NewCVENotFoundError(cveID)

	if err.Err != ErrCVENotFound {
		t.Errorf("NewCVENotFoundError().Err = %v, want %v", err.Err, ErrCVENotFound)
	}

	expectedMessage := "CVE CVE-2023-1234 not found in any available database"
	if err.Message != expectedMessage {
		t.Errorf("NewCVENotFoundError().Message = %v, want %v", err.Message, expectedMessage)
	}

	if err.StatusCode != http.StatusNotFound {
		t.Errorf("NewCVENotFoundError().StatusCode = %v, want %v", err.StatusCode, http.StatusNotFound)
	}

	if err.CVE != cveID {
		t.Errorf("NewCVENotFoundError().CVE = %v, want %v", err.CVE, cveID)
	}
}

func TestNewInvalidCVEError(t *testing.T) {
	cveID := "invalid-cve"
	err := NewInvalidCVEError(cveID)

	if err.Err != ErrInvalidCVEID {
		t.Errorf("NewInvalidCVEError().Err = %v, want %v", err.Err, ErrInvalidCVEID)
	}

	expectedMessage := "invalid CVE ID format: invalid-cve"
	if err.Message != expectedMessage {
		t.Errorf("NewInvalidCVEError().Message = %v, want %v", err.Message, expectedMessage)
	}

	if err.StatusCode != http.StatusBadRequest {
		t.Errorf("NewInvalidCVEError().StatusCode = %v, want %v", err.StatusCode, http.StatusBadRequest)
	}

	if err.CVE != cveID {
		t.Errorf("NewInvalidCVEError().CVE = %v, want %v", err.CVE, cveID)
	}
}

func TestNewServiceError(t *testing.T) {
	underlyingErr := errors.New("connection failed")
	source := "NVD"
	cveID := "CVE-2023-1234"
	
	err := NewServiceError(underlyingErr, source, cveID)

	if err.Err != underlyingErr {
		t.Errorf("NewServiceError().Err = %v, want %v", err.Err, underlyingErr)
	}

	expectedMessage := "NVD service error for CVE-2023-1234: connection failed"
	if err.Message != expectedMessage {
		t.Errorf("NewServiceError().Message = %v, want %v", err.Message, expectedMessage)
	}

	if err.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("NewServiceError().StatusCode = %v, want %v", err.StatusCode, http.StatusServiceUnavailable)
	}

	if err.Source != source {
		t.Errorf("NewServiceError().Source = %v, want %v", err.Source, source)
	}

	if err.CVE != cveID {
		t.Errorf("NewServiceError().CVE = %v, want %v", err.CVE, cveID)
	}
}

func TestErrorConstants(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrCVENotFound",
			err:  ErrCVENotFound,
			want: "CVE not found",
		},
		{
			name: "ErrInvalidCVEID",
			err:  ErrInvalidCVEID,
			want: "invalid CVE ID format",
		},
		{
			name: "ErrEmptyCVEID",
			err:  ErrEmptyCVEID,
			want: "CVE ID is required",
		},
		{
			name: "ErrServiceTimeout",
			err:  ErrServiceTimeout,
			want: "service timeout",
		},
		{
			name: "ErrRateLimited",
			err:  ErrRateLimited,
			want: "rate limited",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.want {
				t.Errorf("Error constant %s = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestAppError_ErrorsIs(t *testing.T) {
	underlyingErr := ErrCVENotFound
	appErr := &AppError{
		Err:     underlyingErr,
		Message: "custom message",
	}

	// Test that errors.Is works with wrapped errors
	if !errors.Is(appErr, ErrCVENotFound) {
		t.Error("AppError should wrap the underlying error properly for errors.Is")
	}

	// Test that errors.Is returns false for different errors
	if errors.Is(appErr, ErrInvalidCVEID) {
		t.Error("AppError should not match different underlying errors")
	}
}