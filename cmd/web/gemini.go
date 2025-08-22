package main

import (
	"context"
	"fmt"
	"os"

	"github.com/google/generative-ai-go/genai"
	"vuln_analyzer/internal/models"

	"google.golang.org/api/option"
)

// GeminiService provides AI-powered CVE analysis using Google's Gemini API.
type GeminiService struct {
	client *genai.GenerativeModel
}

// NewGeminiService creates a new Gemini service instance.
// Requires GEMINI_API_KEY environment variable to be set.
func NewGeminiService() (*GeminiService, error) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY environment variable not set")
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	model := client.GenerativeModel("gemini-1.5-flash")

	return &GeminiService{client: model}, nil
}

// AnalyzeCVE generates a comprehensive CVE analysis using AI.
func (s *GeminiService) AnalyzeCVE(ctx context.Context, cveData *models.CVEData, webResults string) (string, error) {
	prompt := genai.Text(fmt.Sprintf(`
		You are a security analyst specializing in vulnerability analysis. Create a clear, specific summary using ALL available information from multiple sources.

		**CRITICAL: Use all available information to create the most comprehensive analysis possible. The CVE data may come from multiple official databases (NVD, OSV) and web search results may include GitHub Security Advisories plus search engine results. Synthesize all this information for a complete picture.**

		**CVE Database Information:**
		- **ID:** %s
		- **Description:** %s  
		- **Severity:** %s (CVSS Score: %.1f)
		- **Data Sources:** This CVE information has been aggregated from multiple official vulnerability databases (NVD, OSV) to provide the most complete picture.

		**Additional Context from Web Search (GitHub + Search Engines):**
		%s

		**Required Response Format:**
		Use these exact markdown headers:

		### What Happened
		FIRST: If this is a well-known vulnerability with a common name (e.g., WannaCry, EternalBlue), state it clearly. Then explain the core vulnerability in 1-2 sentences. Include affected software/systems if known from web results.

		### How It Happened  
		Explain the technical root cause (buffer overflow, deserialization, etc.). Describe the attack vector/method. Use specific details from web search results when available.

		### Why You Should Care
		State the direct impact (what attackers can achieve). Include any notable real-world exploitation mentioned in web results. Provide severity context with CVSS score. ONLY include action items if they are specific (e.g., "update WinRAR to version X").

		### Sources
		- List any URLs from the web search results that provided information
		- Only include if web search results contain URLs

		**Quality Requirements:**
		- If web search results contain specific information, prioritize them over generic CVE descriptions
		- If only CVE database information is available, extract maximum useful details from it
		- Be specific when information is available, acknowledge limitations when it isn't
		- Connect the vulnerability to its real-world significance when possible
		- Never refuse to provide analysis due to limited information - work with what's available
	`, cveData.ID, cveData.Description, cveData.Severity, cveData.Score, webResults))

	resp, err := s.client.GenerateContent(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("error during content generation: %w", err)
	}

	if len(resp.Candidates) > 0 {
		for _, cand := range resp.Candidates {
			if cand.Content != nil {
				for _, part := range cand.Content.Parts {
					if txt, ok := part.(genai.Text); ok {
						return string(txt), nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("no content generated")
}
