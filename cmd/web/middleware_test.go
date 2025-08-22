package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRequestID(t *testing.T) {
	tests := []struct {
		name           string
		existingID     string
		expectNewID    bool
		description    string
	}{
		{
			name:        "no_existing_request_id",
			existingID:  "",
			expectNewID: true,
			description: "should generate new UUID when no X-Request-ID header",
		},
		{
			name:        "existing_request_id",
			existingID:  "existing-123",
			expectNewID: false,
			description: "should use existing X-Request-ID header",
		},
		{
			name:        "empty_request_id_header",
			existingID:  "",
			expectNewID: true,
			description: "should generate new UUID when X-Request-ID header is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that checks the context and response headers
			var capturedRequestID string
			var contextRequestID interface{}
			
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedRequestID = w.Header().Get("X-Request-ID")
				contextRequestID = r.Context().Value("request_id")
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with RequestID middleware
			middleware := RequestID(testHandler)

			// Create request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.existingID != "" {
				req.Header.Set("X-Request-ID", tt.existingID)
			}

			// Create response recorder
			recorder := httptest.NewRecorder()

			// Execute request
			middleware.ServeHTTP(recorder, req)

			// Verify response header
			responseID := recorder.Header().Get("X-Request-ID")
			if responseID == "" {
				t.Error("RequestID middleware did not set X-Request-ID response header")
				return
			}

			// Verify captured ID matches response header
			if capturedRequestID != responseID {
				t.Errorf("Captured ID %v does not match response header %v", capturedRequestID, responseID)
			}

			// Verify context value matches
			if contextRequestID != responseID {
				t.Errorf("Context value %v does not match response header %v", contextRequestID, responseID)
			}

			if tt.expectNewID {
				// Should be a valid UUID
				if _, err := uuid.Parse(responseID); err != nil {
					t.Errorf("Generated request ID %v is not a valid UUID: %v", responseID, err)
				}
				
				// Should not match existing ID (if any)
				if tt.existingID != "" && responseID == tt.existingID {
					t.Error("Expected new UUID but got existing ID")
				}
			} else {
				// Should match existing ID
				if responseID != tt.existingID {
					t.Errorf("Expected existing ID %v, got %v", tt.existingID, responseID)
				}
			}
		})
	}
}

func TestRecovery(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectPanic    bool
		expectedStatus int
		expectedBody   string
		description    string
	}{
		{
			name: "no_panic",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			}),
			expectPanic:    false,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
			description:    "should pass through normal handlers without interference",
		},
		{
			name: "panic_with_string",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("test panic")
			}),
			expectPanic:    true,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal Server Error\n",
			description:    "should recover from string panic and return 500",
		},
		{
			name: "panic_with_error",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic(fmt.Errorf("test error panic"))
			}),
			expectPanic:    true,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal Server Error\n",
			description:    "should recover from error panic and return 500",
		},
		{
			name: "panic_with_nil",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic(nil)
			}),
			expectPanic:    true, // panic(nil) does trigger recover
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal Server Error\n",
			description:    "should handle panic(nil) gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a buffer to capture log output
			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			// Wrap handler with Recovery middleware
			middleware := Recovery(logger)(tt.handler)

			// Create request and recorder
			req := httptest.NewRequest("GET", "/test", nil)
			recorder := httptest.NewRecorder()

			// Execute request
			middleware.ServeHTTP(recorder, req)

			// Check status code
			if recorder.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, recorder.Code)
			}

			// Check response body
			body := recorder.Body.String()
			if body != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
			}

			// Check if panic was logged
			logOutput := logBuf.String()
			if tt.expectPanic {
				if !strings.Contains(logOutput, "Panic recovered") {
					t.Error("Expected panic to be logged, but no log entry found")
				}
				if !strings.Contains(logOutput, "/test") {
					t.Error("Expected request path to be logged")
				}
				if !strings.Contains(logOutput, "GET") {
					t.Error("Expected request method to be logged")
				}
			} else {
				if strings.Contains(logOutput, "Panic recovered") {
					t.Error("Unexpected panic log entry found")
				}
			}
		})
	}
}

func TestSecurity(t *testing.T) {
	expectedHeaders := map[string]string{
		"X-Content-Type-Options":   "nosniff",
		"X-Frame-Options":          "DENY",
		"X-XSS-Protection":         "1; mode=block",
		"Referrer-Policy":          "strict-origin-when-cross-origin",
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Wrap with Security middleware
	middleware := Security(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	recorder := httptest.NewRecorder()

	// Execute request
	middleware.ServeHTTP(recorder, req)

	// Check that all security headers are set
	for headerName, expectedValue := range expectedHeaders {
		actualValue := recorder.Header().Get(headerName)
		if actualValue != expectedValue {
			t.Errorf("Security header %s = %q, want %q", headerName, actualValue, expectedValue)
		}
	}

	// Verify the underlying handler was called
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	if body != "test response" {
		t.Errorf("Expected body %q, got %q", "test response", body)
	}
}

func TestMiddlewareChaining(t *testing.T) {
	// Test that multiple middleware can be chained together
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Base handler that returns request ID from context
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Context().Value("request_id")
		if requestID != nil {
			w.Header().Set("Test-Request-ID", requestID.(string))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("chained"))
	})

	// Chain all middleware: Security -> Recovery -> RequestID -> baseHandler
	handler := Security(Recovery(logger)(RequestID(baseHandler)))

	req := httptest.NewRequest("GET", "/test", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	// Verify all middleware applied their effects
	
	// Security middleware should set headers
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("Security middleware did not apply")
	}

	// RequestID middleware should set request ID
	requestID := recorder.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Error("RequestID middleware did not apply")
	}

	// Base handler should receive the request ID in context
	testRequestID := recorder.Header().Get("Test-Request-ID")
	if testRequestID != requestID {
		t.Error("Request ID not properly passed through context")
	}

	// Response should be from base handler
	if recorder.Body.String() != "chained" {
		t.Error("Base handler did not execute")
	}
}

func TestRecovery_LogContent(t *testing.T) {
	// Test that recovery logs contain expected information
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic message")
	})

	middleware := Recovery(logger)(panicHandler)

	req := httptest.NewRequest("POST", "/api/test?param=value", nil)
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	logOutput := logBuf.String()

	// Verify log contains expected fields
	expectedContent := []string{
		"Panic recovered",
		"test panic message",
		"/api/test",
		"POST",
	}

	for _, content := range expectedContent {
		if !strings.Contains(logOutput, content) {
			t.Errorf("Log output should contain %q, but got: %s", content, logOutput)
		}
	}
}

func TestRequestID_ContextPropagation(t *testing.T) {
	// Test that request ID is properly available in nested contexts
	var receivedID string
	
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate nested context usage
		ctx := r.Context()
		
		// Create a new context from the request context
		newCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		
		// The request ID should still be available in the new context
		if id := newCtx.Value("request_id"); id != nil {
			receivedID = id.(string)
		}
		
		w.WriteHeader(http.StatusOK)
	})

	middleware := RequestID(testHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	responseID := recorder.Header().Get("X-Request-ID")
	
	if receivedID != responseID {
		t.Errorf("Context propagation failed: received %q, expected %q", receivedID, responseID)
	}

	if receivedID == "" {
		t.Error("Request ID not available in nested context")
	}
}

func TestSecurity_HeaderOverride(t *testing.T) {
	// Test that security middleware doesn't override headers set by the handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler tries to set a conflicting header
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.WriteHeader(http.StatusOK)
	})

	middleware := Security(testHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	// Security middleware sets headers before calling the handler,
	// so the handler's attempt to override should win
	frameOptions := recorder.Header().Get("X-Frame-Options")
	if frameOptions != "SAMEORIGIN" {
		t.Errorf("Expected handler to override header, got %q", frameOptions)
	}
}