// Package models defines the core data structures for CVE information.
package models

import (
	"regexp"
	"strings"

	"vuln_analyzer/internal/errors"
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

// CVEIDRegex matches valid CVE ID format (CVE-YYYY-NNNN)
var CVEIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ValidateCVEID validates and normalizes a CVE ID.
func ValidateCVEID(cveID string) (string, error) {
	if cveID == "" {
		return "", errors.ErrEmptyCVEID
	}

	normalized := strings.ToUpper(strings.TrimSpace(cveID))
	if !CVEIDRegex.MatchString(normalized) {
		return "", errors.ErrInvalidCVEID
	}

	return normalized, nil
}

// NVDResponse is the structure for the NVD API response.
type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Description struct {
				DescriptionData []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			Published string `json:"published"`
			Modified  string `json:"lastModified"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}
