package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	HTTPTimeout = 30 * time.Second
	UserAgent   = "CVE-Analyzer/1.0"
)

func parseCVSSSeverity(score string) string {
	switch {
	case strings.Contains(score, "9."), strings.Contains(score, "10."):
		return "CRITICAL"
	case strings.Contains(score, "7."), strings.Contains(score, "8."):
		return "HIGH"
	case strings.Contains(score, "4."), strings.Contains(score, "5."), strings.Contains(score, "6."):
		return "MEDIUM"
	default:
		return "LOW"
	}
}

var tagRegexp = regexp.MustCompile("<[^>]*>")

func cleanText(text string) string {
	text = tagRegexp.ReplaceAllString(text, "")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	text = strings.ReplaceAll(text, "&#39;", "'")
	return strings.Join(strings.Fields(text), " ")
}

// GitHub Provider
type GitHub struct {
	client *http.Client
	URL    string
}

func NewGitHub() *GitHub {
	return &GitHub{
		client: &http.Client{Timeout: HTTPTimeout},
		URL:    "https://api.github.com/advisories",
	}
}

func (p *GitHub) Search(ctx context.Context, cveID string) (*SearchResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.URL+"?cve_id="+cveID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github returned %d", resp.StatusCode)
	}

	var ads []struct {
		Summary     string `json:"summary"`
		Description string `json:"description"`
		URL         string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ads); err != nil {
		return nil, err
	}

	res := &SearchResult{
		SourceStatus: map[string]bool{"GitHub": len(ads) > 0},
	}

	var sb strings.Builder
	if len(ads) > 0 {
		sb.WriteString("### Additional Resources\n")
		for i, a := range ads {
			if i >= 3 {
				break
			}
			title := cleanText(a.Summary)
			desc := cleanText(a.Description)
			if len(desc) > 300 {
				desc = desc[:297] + "..."
			}
			fmt.Fprintf(&sb, "- [%s](%s)\n  %s\n\n", title, a.URL, desc)
		}
	} else {
		sb.WriteString("No additional context found.")
	}
	res.Content = sb.String()

	return res, nil
}

// NVD Provider
type NVD struct {
	apiKey string
	client *http.Client
	URL    string
}

func NewNVD(apiKey string) *NVD {
	return &NVD{
		apiKey: apiKey,
		client: &http.Client{Timeout: HTTPTimeout},
		URL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

func (p *NVD) Name() string { return "NVD" }

func (p *NVD) Fetch(ctx context.Context, cveID string) (*CVEData, error) {
	if p.apiKey == "" {
		return nil, ErrMissingAPIKey
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.URL+"?cveId="+cveID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("apiKey", p.apiKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrCVENotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("nvd returned status %d: %s", resp.StatusCode, string(body))
	}

	var res struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Modified     string `json:"lastModified"`
				Descriptions []struct {
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					V31 []struct {
						Data struct {
							Score    float64 `json:"baseScore"`
							Severity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					V30 []struct {
						Data struct {
							Score    float64 `json:"baseScore"`
							Severity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode nvd response: %w", err)
	}

	if len(res.Vulnerabilities) == 0 {
		return nil, ErrCVENotFound
	}

	v := res.Vulnerabilities[0].CVE
	data := &CVEData{
		ID:        v.ID,
		Published: v.Published,
		Modified:  v.Modified,
	}

	if len(v.Descriptions) > 0 {
		data.Description = v.Descriptions[0].Value
	}

	if len(v.Metrics.V31) > 0 {
		data.Score = v.Metrics.V31[0].Data.Score
		data.Severity = v.Metrics.V31[0].Data.Severity
	} else if len(v.Metrics.V30) > 0 {
		data.Score = v.Metrics.V30[0].Data.Score
		data.Severity = v.Metrics.V30[0].Data.Severity
	}

	for _, r := range v.References {
		data.References = append(data.References, r.URL)
	}

	return data, nil
}

// OSV Provider
type OSV struct {
	client *http.Client
	URL    string
}

func NewOSV() *OSV {
	return &OSV{
		client: &http.Client{Timeout: HTTPTimeout},
		URL:    "https://api.osv.dev/v1",
	}
}

func (p *OSV) Name() string { return "OSV" }

func (p *OSV) Fetch(ctx context.Context, cveID string) (*CVEData, error) {
	query := map[string]string{"cve": cveID}
	body, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.URL+"/query", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv returned status %d", resp.StatusCode)
	}

	var res struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Details  string `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			Published string `json:"published"`
			Modified  string `json:"modified"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}

	if len(res.Vulns) == 0 {
		return nil, ErrCVENotFound
	}

	// Pick the first vulnerability found
	v := res.Vulns[0]
	data := &CVEData{
		ID:          v.ID,
		Description: v.Summary,
		Published:   v.Published,
		Modified:    v.Modified,
	}
	if data.Description == "" {
		data.Description = v.Details
	}

	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			data.Severity = parseCVSSSeverity(s.Score)
			break
		}
	}

	for _, r := range v.References {
		data.References = append(data.References, r.URL)
	}

	return data, nil
}
