package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vuln_analyzer/internal/errors"
	"vuln_analyzer/internal/models"
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

type OSVService struct {
	client *http.Client
}

func NewOSVService() *OSVService {
	return &OSVService{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *OSVService) Fetch(cveID string) (*models.CVEData, error) {
	url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", cveID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.NewServiceError(err, "OSV", cveID)
	}

	req.Header.Set("User-Agent", "CVE-Analyzer/1.0")

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

	// Parse severity information
	for _, sev := range osvResp.Severity {
		if sev.Type == "CVSS_V3" {
			if strings.Contains(sev.Score, "9.") || strings.Contains(sev.Score, "10.") {
				cveData.Severity = "CRITICAL"
			} else if strings.Contains(sev.Score, "7.") || strings.Contains(sev.Score, "8.") {
				cveData.Severity = "HIGH"
			} else if strings.Contains(sev.Score, "4.") || strings.Contains(sev.Score, "6.") {
				cveData.Severity = "MEDIUM"
			} else {
				cveData.Severity = "LOW"
			}
		}
	}

	// Extract references
	for _, ref := range osvResp.References {
		cveData.References = append(cveData.References, ref.URL)
	}

	return cveData, nil
}