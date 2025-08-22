package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"vuln_analyzer/internal/cve"
)

// WebSearchService provides web search capabilities for CVE-related information.
type WebSearchService struct {
	client *http.Client
}

type searchResult struct {
	title   string
	snippet string
	url     string
}

// NewWebSearchService creates a new web search service instance.
func NewWebSearchService() *WebSearchService {
	return &WebSearchService{
		client: &http.Client{Timeout: HTTPTimeout},
	}
}

func (s *WebSearchService) Search(ctx context.Context, cveID string) (*cve.SearchResult, error) {
	sourceStatus := map[string]bool{
		"GitHub":     false,
		"DuckDuckGo": false,
		"Bing":       false,
	}

	var allResults []searchResult
	var lastErr error

	// Always try GitHub first
	githubResults, githubErr := s.searchGitHubAdvisories(ctx, cveID)
	if githubErr != nil {
		lastErr = githubErr
	} else if len(githubResults) > 0 {
		sourceStatus["GitHub"] = true
		allResults = append(allResults, githubResults...)
	}

	// Also try search engines regardless of GitHub results
	searchEngines := []struct {
		name string
		fn   func(context.Context, string) ([]searchResult, error)
	}{
		{"DuckDuckGo", s.searchDuckDuckGoResults},
	}

	for _, engine := range searchEngines {
		results, err := engine.fn(ctx, cveID)
		if err != nil {
			lastErr = err
			continue
		}

		if len(results) > 0 {
			sourceStatus[engine.name] = true
			allResults = append(allResults, results...)
			break // Use first successful search engine
		}
	}

	var content string
	if len(allResults) == 0 {
		if lastErr != nil {
			content = fmt.Sprintf("**Web Search Status:** Unable to retrieve additional web context for %s due to search service limitations.", cveID)
		} else {
			content = fmt.Sprintf("No additional web search results found for %s", cveID)
		}
	} else {
		content = s.formatResults(allResults)
	}

	return &cve.SearchResult{
		Content:      content,
		SourceStatus: sourceStatus,
	}, nil
}

func (s *WebSearchService) searchGitHubAdvisories(ctx context.Context, cveID string) ([]searchResult, error) {
	apiURL := fmt.Sprintf("https://api.github.com/advisories?cve_id=%s", cveID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned status %d", resp.StatusCode)
	}

	var advisories []struct {
		Summary     string `json:"summary"`
		Description string `json:"description"`
		HTMLURL     string `json:"html_url"`
		Severity    string `json:"severity"`
		CVEID       string `json:"cve_id"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read GitHub response: %w", err)
	}

	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub response: %w", err)
	}

	var results []searchResult
	for _, advisory := range advisories {
		if len(results) >= 3 { // Limit results
			break
		}

		title := fmt.Sprintf("GitHub Advisory: %s", advisory.Summary)
		snippet := advisory.Description
		if len(snippet) > 300 {
			snippet = snippet[:297] + "..."
		}

		results = append(results, searchResult{
			title:   s.cleanText(title),
			snippet: s.cleanText(snippet),
			url:     advisory.HTMLURL,
		})
	}

	return results, nil
}

func (s *WebSearchService) searchDuckDuckGoResults(ctx context.Context, cveID string) ([]searchResult, error) {
	query := url.QueryEscape(fmt.Sprintf("%s vulnerability security", cveID))
	apiURL := fmt.Sprintf("https://api.duckduckgo.com/?q=%s&format=json&no_html=1&skip_disambig=1", query)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DuckDuckGo request: %w", err)
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DuckDuckGo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DuckDuckGo returned status %d", resp.StatusCode)
	}

	var ddgResp struct {
		Abstract      string `json:"Abstract"`
		AbstractText  string `json:"AbstractText"`
		AbstractURL   string `json:"AbstractUrl"`
		RelatedTopics []struct {
			Text string `json:"Text"`
			URL  string `json:"FirstURL"`
		} `json:"RelatedTopics"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DuckDuckGo response: %w", err)
	}

	if err := json.Unmarshal(body, &ddgResp); err != nil {
		return []searchResult{}, nil
	}

	var results []searchResult

	// Use abstract if available
	if ddgResp.AbstractText != "" {
		results = append(results, searchResult{
			title:   fmt.Sprintf("%s Information", cveID),
			snippet: ddgResp.AbstractText,
			url:     ddgResp.AbstractURL,
		})
	}

	// Add related topics
	for i, topic := range ddgResp.RelatedTopics {
		if i >= 3 { // Limit to 3 related topics
			break
		}
		if topic.Text != "" {
			results = append(results, searchResult{
				title:   "Related Information",
				snippet: topic.Text,
				url:     topic.URL,
			})
		}
	}

	return results, nil
}

func (s *WebSearchService) cleanText(text string) string {
	// Remove common HTML entities
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	text = strings.ReplaceAll(text, "&#39;", "'")

	// Clean up whitespace
	text = regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(text), " ")

	return text
}

func (s *WebSearchService) formatResults(results []searchResult) string {
	if len(results) == 0 {
		return "No relevant web search results found."
	}

	var formatted strings.Builder
	formatted.WriteString("**Web Search Results:**\n\n")

	var sourceURLs []string

	for i, result := range results {
		if i >= 3 { // Limit to top 3 results to avoid overwhelming the AI
			break
		}

		formatted.WriteString(fmt.Sprintf("**Source %d:**\n", i+1))
		if result.title != "" {
			formatted.WriteString(fmt.Sprintf("- **Title:** %s\n", result.title))
		}
		if result.snippet != "" {
			formatted.WriteString(fmt.Sprintf("- **Summary:** %s\n", result.snippet))
		}
		if result.url != "" {
			sourceURLs = append(sourceURLs, result.url)
			formatted.WriteString(fmt.Sprintf("- **URL:** %s\n", result.url))
		}
		formatted.WriteString("\n")
	}

	// Add instruction for sources section
	if len(sourceURLs) > 0 {
		formatted.WriteString("**INSTRUCTION: Include a 'Sources' section at the end with these URLs as proper markdown links:**\n")
		for i, url := range sourceURLs {
			if i < len(results) && results[i].title != "" {
				// Clean up title for better display
				linkTitle := results[i].title
				if strings.HasPrefix(linkTitle, "GitHub Advisory: ") {
					linkTitle = "GitHub Security Advisory Entry"
				} else if strings.HasPrefix(linkTitle, "Related Information") {
					linkTitle = "Additional Information"
				}
				formatted.WriteString(fmt.Sprintf("- [%s](%s)\n", linkTitle, url))
			} else {
				formatted.WriteString(fmt.Sprintf("- [Reference %d](%s)\n", i+1, url))
			}
		}
	}

	return formatted.String()
}
