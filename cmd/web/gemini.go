package main

import (
	"context"
	"fmt"
	"os"

	"vuln_analyzer/internal/models"
	"github.com/google/generative-ai-go/genai"
	
	"google.golang.org/api/option"
)

type GeminiService struct {
	client *genai.GenerativeModel
}

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

func (s *GeminiService) GenerateSummary(cveData *models.CVEData) (string, error) {
	prompt := genai.Text(fmt.Sprintf(`
		You are a security analyst. Create a clear, specific summary of this vulnerability:

		**CVE Information:**
		- **ID:** %s
		- **Description:** %s  
		- **Severity:** %s (CVSS Score: %.1f)

		**Required Response Format:**
		Use these exact markdown headers:

		### What Happened
		Explain the core vulnerability in 1-2 sentences. Include affected software/systems if known.

		### How It Happened  
		Explain the technical root cause (buffer overflow, injection, etc.). Describe the attack vector.

		### Why You Should Care
		State the direct impact (what attackers can achieve). Include severity context with CVSS score.

		**Quality Requirements:**
		- Be specific when information is available
		- Connect the vulnerability to its real-world significance when possible
		- Keep each section concise but informative
	`, cveData.ID, cveData.Description, cveData.Severity, cveData.Score))

	ctx := context.Background()
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