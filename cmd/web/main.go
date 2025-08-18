package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	"vuln_analyzer/internal/models"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Server failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	server, err := newServer()
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	return server.run()
}

func (s *server) handleCVE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	var req struct {
		CVE string `json:"cve"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "")
		return
	}

	// Validate CVE format
	if req.CVE == "" {
		writeErrorResponse(w, http.StatusBadRequest, "CVE ID is required", "")
		return
	}
	
	// Normalize and validate CVE format
	req.CVE = strings.ToUpper(strings.TrimSpace(req.CVE))
	cveRegex := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	if !cveRegex.MatchString(req.CVE) {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid CVE format (expected CVE-YYYY-NNNN)", req.CVE)
		return
	}

	logger := s.logger.WithCVE(req.CVE)
	logger.Info("Processing CVE request")

	// Fetch CVE data from sources
	var cveData *models.CVEData
	var source string

	// Try NVD first
	if data, err := s.nvdService.Fetch(req.CVE); err != nil {
		logger.Warn("NVD fetch failed", slog.String("error", err.Error()))
	} else {
		cveData = data
		source = "NVD"
		logger.Info("Successfully fetched from NVD")
	}

	// Fallback to OSV if NVD failed
	if cveData == nil {
		logger.Info("Trying OSV fallback")
		if data, err := s.osvService.Fetch(req.CVE); err != nil {
			logger.Error("OSV fetch failed", slog.String("error", err.Error()))
			writeErrorResponse(w, http.StatusNotFound, fmt.Sprintf("CVE %s not found", req.CVE), req.CVE)
			return
		} else {
			cveData = data
			source = "OSV"
			logger.Info("Successfully fetched from OSV")
		}
	}

	// Perform web search
	webResult, err := s.webSearchService.Search(r.Context(), req.CVE)
	var webContent string
	if err != nil {
		logger.Warn("Web search failed", slog.String("error", err.Error()))
		webContent = "**Web Search Status:** Unable to retrieve additional web context."
	} else {
		webContent = webResult.Content
	}

	// Generate AI summary with web context
	summary, err := s.geminiService.GenerateSummary(cveData, webContent)
	if err != nil {
		logger.Warn("Failed to generate AI summary", slog.String("error", err.Error()))
		summary = fmt.Sprintf("**CVE:** %s\n\n**Description:** %s\n\n**Severity:** %s (%.1f)\n\n%s", 
			cveData.ID, cveData.Description, cveData.Severity, cveData.Score, webContent)
	}

	response := map[string]interface{}{
		"source":  source,
		"summary": summary,
	}

	logger.Info("Successfully processed CVE request", slog.String("source", source))

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		logger.Error("Failed to write response", slog.String("error", err.Error()))
	}
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./ui/html/index.html")
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"healthy"}`)
}

