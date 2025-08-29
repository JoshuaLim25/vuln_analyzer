package app

import (
	"errors"
	"regexp"
	"strings"
)

// Common errors
var (
	ErrCVENotFound    = errors.New("CVE not found")
	ErrInvalidCVEID   = errors.New("invalid CVE ID format")
	ErrEmptyCVEID     = errors.New("CVE ID is required")
	ErrServiceTimeout = errors.New("service timeout")
	ErrRateLimited    = errors.New("rate limited")
	ErrMissingAPIKey  = errors.New("missing service API key")
)

// CVERequest represents a request for CVE information.
type CVERequest struct {
	CVE string `json:"cve"`
}

// CVEData represents normalized CVE information from various sources.
type CVEData struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	References  []string `json:"references"`
	Published   string   `json:"published"`
	Modified    string   `json:"modified"`
}

// SearchResult contains both the formatted results and source status information.
type SearchResult struct {
	Content      string          `json:"content"`
	SourceStatus map[string]bool `json:"source_status"`
}

// CVEIDRegex matches valid CVE ID format (CVE-YYYY-NNNN)
var CVEIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ValidateCVEID validates and normalizes a CVE ID.
func ValidateCVEID(cveID string) (string, error) {
	if cveID == "" {
		return "", ErrEmptyCVEID
	}

	normalized := strings.ToUpper(strings.TrimSpace(cveID))
	if !CVEIDRegex.MatchString(normalized) {
		return "", ErrInvalidCVEID
	}

	return normalized, nil
}
