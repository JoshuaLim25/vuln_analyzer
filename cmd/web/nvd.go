package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"vuln_analyzer/internal/errors"
	"vuln_analyzer/internal/models"
)

const (
	NVDAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

// NVDService provides CVE data fetching from the National Vulnerability Database.
type NVDService struct {
	apiKey string
	client *http.Client
}

// NewNVDService creates a new NVD service instance.
// Requires NVD_API_KEY environment variable to be set.
func NewNVDService() (*NVDService, error) {
	apiKey := os.Getenv("NVD_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("NVD_API_KEY environment variable not set")
	}

	return &NVDService{
		apiKey: apiKey,
		client: &http.Client{Timeout: HTTPTimeout},
	}, nil
}

// Fetch retrieves CVE data from the NVD API.
func (s *NVDService) Fetch(ctx context.Context, cveID string) (*models.CVEData, error) {
	url := fmt.Sprintf("%s?cveId=%s", NVDAPIURL, cveID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.NewServiceError(err, "NVD", cveID)
	}

	req.Header.Set("apiKey", s.apiKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.NewServiceError(err, "NVD", cveID)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.NewCVENotFoundError(cveID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewServiceError(
			fmt.Errorf("status code: %d", resp.StatusCode),
			"NVD", cveID)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.NewServiceError(err, "NVD", cveID)
	}

	var nvdResp models.NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, errors.NewServiceError(err, "NVD", cveID)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, errors.NewCVENotFoundError(cveID)
	}

	vuln := nvdResp.Vulnerabilities[0].CVE
	cveData := &models.CVEData{
		ID:        vuln.ID,
		Published: vuln.Published,
		Modified:  vuln.Modified,
	}

	// Extract description
	if len(vuln.Description.DescriptionData) > 0 {
		cveData.Description = vuln.Description.DescriptionData[0].Value
	}

	// Extract CVSS metrics
	if len(vuln.Metrics.CVSSMetricV31) > 0 {
		cvss := vuln.Metrics.CVSSMetricV31[0].CVSSData
		cveData.Score = cvss.BaseScore
		cveData.Severity = cvss.BaseSeverity
	} else if len(vuln.Metrics.CVSSMetricV30) > 0 {
		cvss := vuln.Metrics.CVSSMetricV30[0].CVSSData
		cveData.Score = cvss.BaseScore
		cveData.Severity = cvss.BaseSeverity
	}

	// Extract references
	for _, ref := range vuln.References {
		cveData.References = append(cveData.References, ref.URL)
	}

	return cveData, nil
}
