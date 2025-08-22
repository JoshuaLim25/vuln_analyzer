// Package cve provides interfaces and types for CVE data fetching and analysis.
package cve

import (
	"context"

	"vuln_analyzer/internal/models"
)

// Fetcher defines the interface for fetching CVE data from various sources.
// Implementations should handle network timeouts, retries, and rate limiting appropriately.
type Fetcher interface {
	// Fetch retrieves CVE data for the given CVE ID.
	// Returns ErrCVENotFound if the CVE doesn't exist in the source.
	Fetch(ctx context.Context, cveID string) (*models.CVEData, error)
}

// Analyzer defines the interface for AI-powered CVE analysis.
type Analyzer interface {
	// AnalyzeCVE generates a comprehensive summary combining CVE data with web research.
	AnalyzeCVE(ctx context.Context, cveData *models.CVEData, webResults string) (string, error)
}

// Searcher defines the interface for web searching CVE-related information.
type Searcher interface {
	// Search performs web searches for CVE-related information.
	Search(ctx context.Context, cveID string) (*SearchResult, error)
}

// SearchResult contains both the formatted results and source status information.
type SearchResult struct {
	Content      string          `json:"content"`
	SourceStatus map[string]bool `json:"source_status"`
}
