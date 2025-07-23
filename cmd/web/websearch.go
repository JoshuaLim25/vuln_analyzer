package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WebSearchService struct {
	client *http.Client
}

type SearchResult struct {
	Content      string            `json:"content"`
	SourceStatus map[string]bool   `json:"source_status"`
}

func NewWebSearchService() *WebSearchService {
	return &WebSearchService{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *WebSearchService) Search(ctx context.Context, cveID string) (*SearchResult, error) {
	sourceStatus := map[string]bool{
		"GitHub":     false,
		"DuckDuckGo": false,
	}

	var results []string

	// Try GitHub Security Advisories
	if githubResult, err := s.searchGitHub(ctx, cveID); err == nil {
		sourceStatus["GitHub"] = true
		results = append(results, githubResult)
	}

	// Try DuckDuckGo search
	if ddgResult, err := s.searchDuckDuckGo(ctx, cveID); err == nil {
		sourceStatus["DuckDuckGo"] = true
		results = append(results, ddgResult)
	}

	content := "No additional web search results found."
	if len(results) > 0 {
		content = strings.Join(results, "\n\n")
	}

	return &SearchResult{
		Content:      content,
		SourceStatus: sourceStatus,
	}, nil
}

func (s *WebSearchService) searchGitHub(ctx context.Context, cveID string) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/advisories?cve_id=%s", cveID)
	
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "CVE-Analyzer/1.0")
	
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub returned status %d", resp.StatusCode)
	}

	var advisories []struct {
		Summary     string `json:"summary"`
		Description string `json:"description"`
		HTMLURL     string `json:"html_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return "", err
	}

	if len(advisories) == 0 {
		return "", fmt.Errorf("no advisories found")
	}

	return fmt.Sprintf("**GitHub Advisory:** %s - %s", 
		advisories[0].Summary, advisories[0].Description), nil
}

func (s *WebSearchService) searchDuckDuckGo(ctx context.Context, cveID string) (string, error) {
	query := url.QueryEscape(fmt.Sprintf("%s vulnerability security", cveID))
	apiURL := fmt.Sprintf("https://api.duckduckgo.com/?q=%s&format=json&no_html=1", query)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var ddgResp struct {
		AbstractText string `json:"AbstractText"`
	}

	if err := json.Unmarshal(body, &ddgResp); err != nil {
		return "", err
	}

	if ddgResp.AbstractText == "" {
		return "", fmt.Errorf("no abstract found")
	}

	return fmt.Sprintf("**Web Search:** %s", ddgResp.AbstractText), nil
}