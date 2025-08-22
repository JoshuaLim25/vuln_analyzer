package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Common HTTP constants
const (
	HTTPTimeout = 30 * time.Second
	UserAgent   = "CVE-Analyzer/1.0"
)

// WriteJSON writes JSON responses with proper content type headers.
func WriteJSON(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// ReadJSON reads and validates JSON request bodies with size limits.
func ReadJSON(r *http.Request, dst any) error {
	// Limit request body size to prevent abuse
	maxBytes := int64(1048576) // 1MB
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Ensure only one JSON object in body
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must only contain a single JSON object")
	}

	return nil
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error string `json:"error"`
	CVE   string `json:"cve,omitempty"`
}

// WriteErrorResponse writes standardized error responses.
func WriteErrorResponse(w http.ResponseWriter, status int, message string, cve string) {
	response := ErrorResponse{
		Error: message,
		CVE:   cve,
	}

	if err := WriteJSON(w, status, response); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
