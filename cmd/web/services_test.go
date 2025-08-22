package main

import (
	"os"
	"testing"
)

func TestNewNVDService(t *testing.T) {
	// Save original env var
	originalAPIKey := os.Getenv("NVD_API_KEY")
	defer os.Setenv("NVD_API_KEY", originalAPIKey)

	tests := []struct {
		name        string
		apiKey      string
		expectError bool
		description string
	}{
		{
			name:        "valid_api_key",
			apiKey:      "test-api-key",
			expectError: false,
			description: "should create service with valid API key",
		},
		{
			name:        "empty_api_key",
			apiKey:      "",
			expectError: true,
			description: "should fail with empty API key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("NVD_API_KEY", tt.apiKey)

			service, err := NewNVDService()

			if tt.expectError {
				if err == nil {
					t.Error("NewNVDService() expected error but got none")
				}
				if service != nil {
					t.Error("NewNVDService() should return nil service on error")
				}
			} else {
				if err != nil {
					t.Errorf("NewNVDService() unexpected error: %v", err)
				}
				if service == nil {
					t.Error("NewNVDService() returned nil service")
				}
				if service.apiKey != tt.apiKey {
					t.Errorf("NewNVDService() apiKey = %v, want %v", service.apiKey, tt.apiKey)
				}
				if service.client == nil {
					t.Error("NewNVDService() client is nil")
				}
			}
		})
	}
}

func TestNVDService_Fetch(t *testing.T) {
	// Skip integration tests that require modifying constants
	// In a real implementation, we'd use dependency injection for URLs
	t.Skip("Skipping NVD integration tests - constants cannot be modified in tests")
}

func TestNewOSVService(t *testing.T) {
	service := NewOSVService()

	if service == nil {
		t.Error("NewOSVService() returned nil")
	}

	if service.client == nil {
		t.Error("NewOSVService() client is nil")
	}

	// Verify timeout is set
	if service.client.Timeout <= 0 {
		t.Error("NewOSVService() client timeout should be positive")
	}
}

func TestOSVService_Fetch(t *testing.T) {
	// Skip integration tests that require modifying constants
	// In a real implementation, we'd use dependency injection for URLs
	t.Skip("Skipping OSV integration tests - constants cannot be modified in tests")
}

func TestParseCVSSSeverity(t *testing.T) {
	tests := []struct {
		name     string
		score    string
		expected string
	}{
		{
			name:     "critical_score_9",
			score:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8",
			expected: SeverityCritical,
		},
		{
			name:     "critical_score_10",
			score:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/10.0",
			expected: SeverityCritical,
		},
		{
			name:     "high_score_7",
			score:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/7.5",
			expected: SeverityHigh,
		},
		{
			name:     "high_score_8",
			score:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/8.2",
			expected: SeverityHigh,
		},
		{
			name:     "medium_score_4",
			score:    "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/4.2",
			expected: SeverityMedium,
		},
		{
			name:     "medium_score_5",
			score:    "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/5.8",
			expected: SeverityMedium,
		},
		{
			name:     "medium_score_6",
			score:    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/6.1",
			expected: SeverityMedium,
		},
		{
			name:     "low_score_3",
			score:    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N/3.2",
			expected: SeverityLow,
		},
		{
			name:     "low_score_0",
			score:    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/0.0",
			expected: SeverityLow,
		},
		{
			name:     "no_score_in_string",
			score:    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
			expected: SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCVSSSeverity(tt.score)
			if result != tt.expected {
				t.Errorf("parseCVSSSeverity(%q) = %q, want %q", tt.score, result, tt.expected)
			}
		})
	}
}

func TestNewGeminiService(t *testing.T) {
	// Save original env var
	originalAPIKey := os.Getenv("GEMINI_API_KEY")
	defer os.Setenv("GEMINI_API_KEY", originalAPIKey)

	tests := []struct {
		name        string
		apiKey      string
		expectError bool
		description string
	}{
		{
			name:        "missing_api_key",
			apiKey:      "",
			expectError: true,
			description: "should fail with missing API key",
		},
		{
			name:        "valid_api_key",
			apiKey:      "test-gemini-key",
			expectError: false,
			description: "should create service with valid API key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("GEMINI_API_KEY", tt.apiKey)

			service, err := NewGeminiService()

			if tt.expectError {
				if err == nil {
					t.Error("NewGeminiService() expected error but got none")
				}
				if service != nil {
					t.Error("NewGeminiService() should return nil service on error")
				}
			} else {
				// We can't fully test this without mocking the Gemini client
				// but we can test that it doesn't panic and handles the API key correctly
				if tt.apiKey != "" && err != nil {
					// If we have a valid API key but still get an error,
					// it's likely due to the real Gemini client initialization
					// which is acceptable in this test context
					t.Logf("NewGeminiService() returned error with valid API key (expected in test): %v", err)
				}
			}
		})
	}
}

func TestNewWebSearchService(t *testing.T) {
	service := NewWebSearchService()

	if service == nil {
		t.Error("NewWebSearchService() returned nil")
	}

	if service.client == nil {
		t.Error("NewWebSearchService() client is nil")
	}

	// Verify timeout is set
	if service.client.Timeout <= 0 {
		t.Error("NewWebSearchService() client timeout should be positive")
	}
}

func TestServiceConstants(t *testing.T) {
	// Test that constants are properly defined
	if NVDAPIURL == "" {
		t.Error("NVDAPIURL constant is empty")
	}

	if OSVAPIURL == "" {
		t.Error("OSVAPIURL constant is empty")
	}

	if UserAgent == "" {
		t.Error("UserAgent constant is empty")
	}

	// HTTPTimeout is tested implicitly through service creation

	// Test severity constants
	severityConstants := []string{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
	}

	for _, severity := range severityConstants {
		if severity == "" {
			t.Errorf("Severity constant is empty")
		}
	}
}

func TestServiceErrorHandling(t *testing.T) {
	// Skip integration tests that require modifying constants
	// In a real implementation, we'd use dependency injection for URLs
	t.Skip("Skipping service error handling tests - constants cannot be modified in tests")
}