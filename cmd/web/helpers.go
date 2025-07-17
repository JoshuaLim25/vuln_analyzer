package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// writeJSON is a helper for writing JSON responses.
func writeJSON(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// readJSON is a helper for reading and decoding JSON requests.
func readJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

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

// writeErrorResponse writes a standardized error response.
func writeErrorResponse(w http.ResponseWriter, status int, message string, cve string) {
	response := ErrorResponse{
		Error: message,
		CVE:   cve,
	}
	
	if err := writeJSON(w, status, response); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}