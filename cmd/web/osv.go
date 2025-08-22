package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"vuln_analyzer/internal/errors"
	"vuln_analyzer/internal/models"
)

const (
	OSVAPIURL = "https://api.osv.dev/v1/vulns"
)

// CVSS severity levels
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// OSVResponse is the structure for the OSV API response.
type OSVResponse struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Published string `json:"published"`
	Modified  string `json:"modified"`
}

// OSVService provides CVE data fetching from the Open Source Vulnerabilities database.
type OSVService struct {
	client *http.Client
}

// NewOSVService creates a new OSV service instance.
func NewOSVService() *OSVService {
	return &OSVService{
		client: &http.Client{Timeout: HTTPTimeout},
	}
}

// Fetch retrieves CVE data from the OSV API.
func (s *OSVService) Fetch(ctx context.Context, cveID string) (*models.CVEData, error) {
	url := fmt.Sprintf("%s/%s", OSVAPIURL, cveID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.NewServiceError(err, "OSV", cveID)
	}

	req.Header.Set("User-Agent", UserAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.NewServiceError(err, "OSV", cveID)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.NewCVENotFoundError(cveID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewServiceError(
			fmt.Errorf("status code: %d", resp.StatusCode),
			"OSV", cveID)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.NewServiceError(err, "OSV", cveID)
	}

	var osvResp OSVResponse
	if err := json.Unmarshal(body, &osvResp); err != nil {
		return nil, errors.NewServiceError(err, "OSV", cveID)
	}

	cveData := &models.CVEData{
		ID:          osvResp.ID,
		Description: osvResp.Summary,
		Published:   osvResp.Published,
		Modified:    osvResp.Modified,
	}

	if cveData.Description == "" {
		cveData.Description = osvResp.Details
	}

	// Parse severity information from CVSS scores
	for _, sev := range osvResp.Severity {
		if sev.Type == "CVSS_V3" {
			cveData.Severity = parseCVSSSeverity(sev.Score)
			break
		}
	}

	// Extract references
	for _, ref := range osvResp.References {
		cveData.References = append(cveData.References, ref.URL)
	}

	return cveData, nil
}

// parseCVSSSeverity converts CVSS score strings to severity levels.
func parseCVSSSeverity(score string) string {
	switch {
	case strings.Contains(score, "9."), strings.Contains(score, "10."):
		return SeverityCritical
	case strings.Contains(score, "7."), strings.Contains(score, "8."):
		return SeverityHigh
	case strings.Contains(score, "4."), strings.Contains(score, "5."), strings.Contains(score, "6."):
		return SeverityMedium
	default:
		return SeverityLow
	}
}
