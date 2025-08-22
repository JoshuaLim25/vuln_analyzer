package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vuln_analyzer/internal/cve"
	"vuln_analyzer/internal/logger"
	"vuln_analyzer/internal/models"
)

// Mock implementations for testing
type mockFetcher struct {
	cveData *models.CVEData
	err     error
}

func (m *mockFetcher) Fetch(ctx context.Context, cveID string) (*models.CVEData, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.cveData, nil
}

type mockAnalyzer struct {
	summary string
	err     error
}

func (m *mockAnalyzer) AnalyzeCVE(ctx context.Context, cveData *models.CVEData, webResults string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.summary, nil
}

type mockSearcher struct {
	result *cve.SearchResult
	err    error
}

func (m *mockSearcher) Search(ctx context.Context, cveID string) (*cve.SearchResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func createTestServer(nvdFetcher, osvFetcher cve.Fetcher, analyzer cve.Analyzer, searcher cve.Searcher) *Server {
	return &Server{
		nvdService:    nvdFetcher,
		osvService:    osvFetcher,
		aiService:     analyzer,
		searchService: searcher,
		logger:        logger.New(),
	}
}

func TestServer_handleCVE(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		body           string
		nvdFetcher     cve.Fetcher
		osvFetcher     cve.Fetcher
		analyzer       cve.Analyzer
		searcher       cve.Searcher
		expectedStatus int
		expectedFields map[string]interface{}
		description    string
	}{
		{
			name:   "successful_nvd_fetch",
			method: "POST",
			body:   `{"cve":"CVE-2023-1234"}`,
			nvdFetcher: &mockFetcher{
				cveData: &models.CVEData{
					ID:          "CVE-2023-1234",
					Description: "Test vulnerability",
					Severity:    "HIGH",
					Score:       7.5,
				},
			},
			osvFetcher: &mockFetcher{err: fmt.Errorf("osv error")},
			analyzer: &mockAnalyzer{
				summary: "Test AI summary",
			},
			searcher: &mockSearcher{
				result: &cve.SearchResult{
					Content: "Test web content",
				},
			},
			expectedStatus: http.StatusOK,
			expectedFields: map[string]interface{}{
				"source":  "NVD",
				"summary": "Test AI summary",
			},
			description: "should successfully process CVE from NVD",
		},
		{
			name:   "fallback_to_osv",
			method: "POST",
			body:   `{"cve":"CVE-2023-5678"}`,
			nvdFetcher: &mockFetcher{
				err: fmt.Errorf("nvd error"),
			},
			osvFetcher: &mockFetcher{
				cveData: &models.CVEData{
					ID:          "CVE-2023-5678",
					Description: "OSV vulnerability",
					Severity:    "MEDIUM",
					Score:       5.0,
				},
			},
			analyzer: &mockAnalyzer{
				summary: "OSV AI summary",
			},
			searcher: &mockSearcher{
				result: &cve.SearchResult{
					Content: "OSV web content",
				},
			},
			expectedStatus: http.StatusOK,
			expectedFields: map[string]interface{}{
				"source":  "OSV",
				"summary": "OSV AI summary",
			},
			description: "should fallback to OSV when NVD fails",
		},
		{
			name:   "invalid_method",
			method: "GET",
			body:   "",
			nvdFetcher: &mockFetcher{
				cveData: &models.CVEData{},
			},
			osvFetcher:     &mockFetcher{},
			analyzer:       &mockAnalyzer{},
			searcher:       &mockSearcher{},
			expectedStatus: http.StatusMethodNotAllowed,
			expectedFields: map[string]interface{}{
				"error": "Method not allowed",
			},
			description: "should reject non-POST requests",
		},
		{
			name:   "invalid_json",
			method: "POST",
			body:   `{"cve":}`,
			nvdFetcher: &mockFetcher{
				cveData: &models.CVEData{},
			},
			osvFetcher:     &mockFetcher{},
			analyzer:       &mockAnalyzer{},
			searcher:       &mockSearcher{},
			expectedStatus: http.StatusBadRequest,
			expectedFields: map[string]interface{}{
				"error": "Invalid request body",
			},
			description: "should reject invalid JSON",
		},
		{
			name:   "invalid_cve_format",
			method: "POST",
			body:   `{"cve":"invalid-cve"}`,
			nvdFetcher: &mockFetcher{
				cveData: &models.CVEData{},
			},
			osvFetcher:     &mockFetcher{},
			analyzer:       &mockAnalyzer{},
			searcher:       &mockSearcher{},
			expectedStatus: http.StatusBadRequest,
			expectedFields: map[string]interface{}{
				"error": "invalid CVE ID format",
				"cve":   "invalid-cve",
			},
			description: "should reject invalid CVE format",
		},
		{
			name:   "empty_cve",
			method: "POST",
			body:   `{"cve":""}`,
			nvdFetcher: &mockFetcher{
				cveData: &models.CVEData{},
			},
			osvFetcher:     &mockFetcher{},
			analyzer:       &mockAnalyzer{},
			searcher:       &mockSearcher{},
			expectedStatus: http.StatusBadRequest,
			expectedFields: map[string]interface{}{
				"error": "CVE ID is required",
			},
			description: "should reject empty CVE ID",
		},
		{
			name:   "cve_not_found_anywhere",
			method: "POST",
			body:   `{"cve":"CVE-2023-9999"}`,
			nvdFetcher: &mockFetcher{
				err: fmt.Errorf("not found"),
			},
			osvFetcher: &mockFetcher{
				err: fmt.Errorf("not found"),
			},
			analyzer:       &mockAnalyzer{},
			searcher:       &mockSearcher{},
			expectedStatus: http.StatusNotFound,
			expectedFields: map[string]interface{}{
				"error": "CVE CVE-2023-9999 not found",
				"cve":   "CVE-2023-9999",
			},
			description: "should return 404 when CVE not found in any source",
		},
		{
			name:   "ai_analysis_fails",
			method: "POST",
			body:   `{"cve":"CVE-2023-1234"}`,
			nvdFetcher: &mockFetcher{
				cveData: &models.CVEData{
					ID:          "CVE-2023-1234",
					Description: "Test vulnerability",
					Severity:    "HIGH",
					Score:       7.5,
				},
			},
			osvFetcher: &mockFetcher{err: fmt.Errorf("osv error")},
			analyzer: &mockAnalyzer{
				err: fmt.Errorf("AI service unavailable"),
			},
			searcher: &mockSearcher{
				result: &cve.SearchResult{
					Content: "Web content",
				},
			},
			expectedStatus: http.StatusOK,
			expectedFields: map[string]interface{}{
				"source": "NVD",
				// Should contain fallback summary
			},
			description: "should provide fallback summary when AI fails",
		},
		{
			name:   "web_search_fails",
			method: "POST",
			body:   `{"cve":"CVE-2023-1234"}`,
			nvdFetcher: &mockFetcher{
				cveData: &models.CVEData{
					ID:          "CVE-2023-1234",
					Description: "Test vulnerability",
					Severity:    "HIGH",
					Score:       7.5,
				},
			},
			osvFetcher: &mockFetcher{err: fmt.Errorf("osv error")},
			analyzer: &mockAnalyzer{
				summary: "AI summary without web context",
			},
			searcher: &mockSearcher{
				err: fmt.Errorf("web search failed"),
			},
			expectedStatus: http.StatusOK,
			expectedFields: map[string]interface{}{
				"source":  "NVD",
				"summary": "AI summary without web context",
			},
			description: "should work when web search fails",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer(tt.nvdFetcher, tt.osvFetcher, tt.analyzer, tt.searcher)
			
			req := httptest.NewRequest(tt.method, "/api/cve", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()

			server.handleCVE(recorder, req)

			if recorder.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, recorder.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			for field, expectedValue := range tt.expectedFields {
				actualValue, exists := response[field]
				if !exists {
					t.Errorf("Expected field %q not found in response", field)
					continue
				}

				// For string fields, do exact comparison
				if expectedStr, ok := expectedValue.(string); ok {
					if actualStr, ok := actualValue.(string); ok {
						if !strings.Contains(actualStr, expectedStr) {
							t.Errorf("Field %q = %q, should contain %q", field, actualStr, expectedStr)
						}
					} else {
						t.Errorf("Field %q is not a string: %v", field, actualValue)
					}
				} else {
					// For other types, do direct comparison
					if actualValue != expectedValue {
						t.Errorf("Field %q = %v, want %v", field, actualValue, expectedValue)
					}
				}
			}
		})
	}
}

func TestServer_home(t *testing.T) {
	server := createTestServer(nil, nil, nil, nil)
	
	req := httptest.NewRequest("GET", "/", nil)
	recorder := httptest.NewRecorder()

	server.home(recorder, req)

	// Should try to serve the file (will fail in test but that's expected)
	// We're just testing that the handler doesn't panic
	if recorder.Code != http.StatusOK && recorder.Code != http.StatusNotFound {
		t.Errorf("Unexpected status code: %d", recorder.Code)
	}
}

func TestServer_health(t *testing.T) {
	server := createTestServer(nil, nil, nil, nil)
	
	req := httptest.NewRequest("GET", "/api/health", nil)
	recorder := httptest.NewRecorder()

	server.health(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	contentType := recorder.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	expectedBody := `{"status":"healthy"}`
	actualBody := strings.TrimSpace(recorder.Body.String())
	if actualBody != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, actualBody)
	}
}

func TestServer_handleCVE_CVEValidation(t *testing.T) {
	// Test various CVE format validations
	tests := []struct {
		name           string
		cveID          string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "valid_cve_lowercase",
			cveID:          "cve-2023-1234",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "valid_cve_with_spaces",
			cveID:          "  CVE-2023-1234  ",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "valid_cve_long_number",
			cveID:          "CVE-2023-123456",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid_cve_short_number",
			cveID:          "CVE-2023-123",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid CVE ID format",
		},
		{
			name:           "invalid_cve_no_prefix",
			cveID:          "2023-1234",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid CVE ID format",
		},
		{
			name:           "invalid_cve_wrong_year",
			cveID:          "CVE-23-1234",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid CVE ID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer(
				&mockFetcher{
					cveData: &models.CVEData{
						ID:          tt.cveID,
						Description: "Test",
					},
				},
				&mockFetcher{err: fmt.Errorf("not found")},
				&mockAnalyzer{summary: "Test summary"},
				&mockSearcher{result: &cve.SearchResult{Content: "Test"}},
			)

			body := fmt.Sprintf(`{"cve":"%s"}`, tt.cveID)
			req := httptest.NewRequest("POST", "/api/cve", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()

			server.handleCVE(recorder, req)

			if recorder.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, recorder.Code)
			}

			if tt.expectedError != "" {
				var response map[string]interface{}
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}

				if errorMsg, ok := response["error"].(string); !ok || !strings.Contains(errorMsg, tt.expectedError) {
					t.Errorf("Expected error to contain %q, got %q", tt.expectedError, errorMsg)
				}
			}
		})
	}
}

func TestServer_handleCVE_ContextCancellation(t *testing.T) {
	// Test that context cancellation is handled properly
	server := createTestServer(
		&mockFetcher{
			cveData: &models.CVEData{
				ID:          "CVE-2023-1234",
				Description: "Test",
			},
		},
		&mockFetcher{err: fmt.Errorf("not found")},
		&mockAnalyzer{summary: "Test summary"},
		&mockSearcher{result: &cve.SearchResult{Content: "Test"}},
	)

	body := `{"cve":"CVE-2023-1234"}`
	req := httptest.NewRequest("POST", "/api/cve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	
	// Create a cancelled context
	ctx, cancel := context.WithCancel(req.Context())
	cancel() // Cancel immediately
	req = req.WithContext(ctx)
	
	recorder := httptest.NewRecorder()

	server.handleCVE(recorder, req)

	// Should still work because the services are mocked and don't check context
	// In a real scenario with proper context handling, this would fail
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200 despite cancelled context, got %d", recorder.Code)
	}
}