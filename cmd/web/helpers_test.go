package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		data           interface{}
		expectedStatus int
		expectedBody   string
		expectError    bool
	}{
		{
			name:           "success_with_map",
			status:         http.StatusOK,
			data:           map[string]string{"message": "success"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
			expectError:    false,
		},
		{
			name:           "success_with_struct",
			status:         http.StatusCreated,
			data:           struct{ Name string }{Name: "test"},
			expectedStatus: http.StatusCreated,
			expectedBody:   `{"Name":"test"}`,
			expectError:    false,
		},
		{
			name:           "success_with_string",
			status:         http.StatusAccepted,
			data:           "plain string",
			expectedStatus: http.StatusAccepted,
			expectedBody:   `"plain string"`,
			expectError:    false,
		},
		{
			name:           "success_with_nil",
			status:         http.StatusNoContent,
			data:           nil,
			expectedStatus: http.StatusNoContent,
			expectedBody:   "null",
			expectError:    false,
		},
		{
			name:           "invalid_json_data",
			status:         http.StatusOK,
			data:           make(chan int), // channels cannot be JSON marshaled
			expectedStatus: http.StatusOK,
			expectedBody:   "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			
			err := WriteJSON(recorder, tt.status, tt.data)
			
			if tt.expectError {
				if err == nil {
					t.Error("WriteJSON() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("WriteJSON() unexpected error: %v", err)
				return
			}

			if recorder.Code != tt.expectedStatus {
				t.Errorf("WriteJSON() status = %v, want %v", recorder.Code, tt.expectedStatus)
			}

			contentType := recorder.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("WriteJSON() Content-Type = %v, want %v", contentType, "application/json")
			}

			body := strings.TrimSpace(recorder.Body.String())
			if body != tt.expectedBody {
				t.Errorf("WriteJSON() body = %v, want %v", body, tt.expectedBody)
			}
		})
	}
}

func TestReadJSON(t *testing.T) {
	type testStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	tests := []struct {
		name        string
		body        string
		target      interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid_json",
			body:        `{"name":"test","value":42}`,
			target:      &testStruct{},
			expectError: false,
		},
		{
			name:        "invalid_json",
			body:        `{"name":"test","value":}`,
			target:      &testStruct{},
			expectError: true,
			errorMsg:    "invalid JSON",
		},
		{
			name:        "unknown_field",
			body:        `{"name":"test","value":42,"unknown":"field"}`,
			target:      &testStruct{},
			expectError: true,
			errorMsg:    "invalid JSON",
		},
		{
			name:        "multiple_json_objects",
			body:        `{"name":"test","value":42}{"name":"test2","value":43}`,
			target:      &testStruct{},
			expectError: true,
			errorMsg:    "request body must only contain a single JSON object",
		},
		{
			name:        "empty_body",
			body:        ``,
			target:      &testStruct{},
			expectError: true,
			errorMsg:    "invalid JSON",
		},
		{
			name:        "large_body_exceeds_limit",
			body:        strings.Repeat("x", 2*1024*1024), // 2MB, exceeds 1MB limit
			target:      &testStruct{},
			expectError: true,
			errorMsg:    "invalid JSON", // MaxBytesReader causes JSON decode error first
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			
			err := ReadJSON(req, tt.target)
			
			if tt.expectError {
				if err == nil {
					t.Error("ReadJSON() expected error but got none")
					return
				}
				
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("ReadJSON() error = %v, should contain %v", err.Error(), tt.errorMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("ReadJSON() unexpected error: %v", err)
				return
			}

			// Verify the data was parsed correctly for valid cases
			if tt.name == "valid_json" {
				result, ok := tt.target.(*testStruct)
				if !ok {
					t.Error("ReadJSON() failed to cast target to testStruct")
					return
				}
				
				if result.Name != "test" || result.Value != 42 {
					t.Errorf("ReadJSON() parsed data incorrectly: got %+v", result)
				}
			}
		})
	}
}

func TestWriteErrorResponse(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		message        string
		cve            string
		expectedStatus int
		expectedBody   ErrorResponse
	}{
		{
			name:           "error_with_cve",
			status:         http.StatusBadRequest,
			message:        "Invalid CVE format",
			cve:            "CVE-2023-1234",
			expectedStatus: http.StatusBadRequest,
			expectedBody: ErrorResponse{
				Error: "Invalid CVE format",
				CVE:   "CVE-2023-1234",
			},
		},
		{
			name:           "error_without_cve",
			status:         http.StatusInternalServerError,
			message:        "Internal server error",
			cve:            "",
			expectedStatus: http.StatusInternalServerError,
			expectedBody: ErrorResponse{
				Error: "Internal server error",
				CVE:   "",
			},
		},
		{
			name:           "not_found_error",
			status:         http.StatusNotFound,
			message:        "CVE not found",
			cve:            "CVE-2023-5678",
			expectedStatus: http.StatusNotFound,
			expectedBody: ErrorResponse{
				Error: "CVE not found",
				CVE:   "CVE-2023-5678",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			
			WriteErrorResponse(recorder, tt.status, tt.message, tt.cve)
			
			if recorder.Code != tt.expectedStatus {
				t.Errorf("WriteErrorResponse() status = %v, want %v", recorder.Code, tt.expectedStatus)
			}

			contentType := recorder.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("WriteErrorResponse() Content-Type = %v, want %v", contentType, "application/json")
			}

			var response ErrorResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Errorf("WriteErrorResponse() failed to unmarshal response: %v", err)
				return
			}

			if response.Error != tt.expectedBody.Error {
				t.Errorf("WriteErrorResponse() error message = %v, want %v", response.Error, tt.expectedBody.Error)
			}

			if response.CVE != tt.expectedBody.CVE {
				t.Errorf("WriteErrorResponse() CVE = %v, want %v", response.CVE, tt.expectedBody.CVE)
			}
		})
	}
}

func TestErrorResponse(t *testing.T) {
	// Test the ErrorResponse struct directly
	tests := []struct {
		name     string
		response ErrorResponse
		wantJSON string
	}{
		{
			name: "with_cve",
			response: ErrorResponse{
				Error: "Test error",
				CVE:   "CVE-2023-1234",
			},
			wantJSON: `{"error":"Test error","cve":"CVE-2023-1234"}`,
		},
		{
			name: "without_cve",
			response: ErrorResponse{
				Error: "Test error",
				CVE:   "",
			},
			wantJSON: `{"error":"Test error"}`, // omitempty excludes empty CVE
		},
		{
			name: "empty_error",
			response: ErrorResponse{
				Error: "",
				CVE:   "CVE-2023-1234",
			},
			wantJSON: `{"error":"","cve":"CVE-2023-1234"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := json.Marshal(tt.response)
			if err != nil {
				t.Errorf("Failed to marshal ErrorResponse: %v", err)
				return
			}

			got := string(jsonBytes)
			if got != tt.wantJSON {
				t.Errorf("ErrorResponse JSON = %v, want %v", got, tt.wantJSON)
			}
		})
	}
}

// Test helper for invalid JSON in WriteJSON
func TestWriteJSON_InvalidResponseWriter(t *testing.T) {
	// Create a mock response writer that fails on Write
	writer := &failingResponseWriter{}
	
	err := WriteJSON(writer, http.StatusOK, map[string]string{"test": "value"})
	
	if err == nil {
		t.Error("WriteJSON() expected error when ResponseWriter fails, got nil")
	}
}

// failingResponseWriter is a mock ResponseWriter that always fails on Write
type failingResponseWriter struct {
	header http.Header
}

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func (w *failingResponseWriter) WriteHeader(statusCode int) {
	// Do nothing
}

func TestReadJSON_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		setupReq    func() *http.Request
		expectError bool
		errorMsg    string
	}{
		{
			name: "nil_body",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", nil)
				return req
			},
			expectError: true,
			errorMsg:    "invalid JSON",
		},
		{
			name: "exact_size_limit",
			setupReq: func() *http.Request {
				// Create exactly 1MB of data
				data := bytes.Repeat([]byte("a"), 1024*1024)
				req := httptest.NewRequest("POST", "/test", bytes.NewReader(data))
				return req
			},
			expectError: true, // Will fail because it's not valid JSON
			errorMsg:    "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			var target map[string]interface{}
			
			err := ReadJSON(req, &target)
			
			if tt.expectError {
				if err == nil {
					t.Error("ReadJSON() expected error but got none")
					return
				}
				
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("ReadJSON() error = %v, should contain %v", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ReadJSON() unexpected error: %v", err)
				}
			}
		})
	}
}