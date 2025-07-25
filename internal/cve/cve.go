// Package cve provides interfaces and types for CVE data fetching.
package cve

import (
	"context"

	"vuln_analyzer/internal/models"
)

// Fetcher defines the interface for fetching CVE data from various sources.
type Fetcher interface {
	Fetch(cveID string) (*models.CVEData, error)
}

type AIAnalyzer interface {
	GenerateSummary(cveData *models.CVEData) (string, error)
}

type WebSearcher interface {
	Search(ctx context.Context, cveID string) (*SearchResult, error)
}

// SearchResult contains both the formatted results and source status information.
type SearchResult struct {
	Content      string            `json:"content"`
	SourceStatus map[string]bool   `json:"source_status"`
}