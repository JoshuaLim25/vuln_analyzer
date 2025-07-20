package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	mux := http.NewServeMux()
	// Static files
	fileServer := http.FileServer(http.Dir("./ui/static/"))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	
	// Routes
	mux.HandleFunc("/", home)
	mux.HandleFunc("/api/health", health)
	mux.HandleFunc("/api/cve", handleCVE)

	log.Printf("Starting server on port %s", port)
	err := http.ListenAndServe(":"+port, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func handleCVE(w http.ResponseWriter, r *http.Request) {
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

	if req.CVE == "" {
		writeErrorResponse(w, http.StatusBadRequest, "CVE ID is required", "")
		return
	}

	log.Printf("Processing CVE request: %s", req.CVE)

	// Fetch CVE data from sources
	var cveData *models.CVEData
	var source string

	// Try NVD first
	nvdService, err := NewNVDService()
	if err == nil {
		if data, err := nvdService.Fetch(req.CVE); err == nil {
			cveData = data
			source = "NVD"
			log.Printf("Successfully fetched %s from NVD", req.CVE)
		} else {
			log.Printf("NVD fetch failed for %s: %v", req.CVE, err)
		}
	}

	// Fallback to OSV if NVD failed
	if cveData == nil {
		log.Printf("Trying OSV fallback for %s", req.CVE)
		osvService := NewOSVService()
		if data, err := osvService.Fetch(req.CVE); err == nil {
			cveData = data
			source = "OSV"
			log.Printf("Successfully fetched %s from OSV", req.CVE)
		} else {
			log.Printf("OSV fetch failed for %s: %v", req.CVE, err)
			writeErrorResponse(w, http.StatusNotFound, fmt.Sprintf("CVE %s not found", req.CVE), req.CVE)
			return
		}
	}

	// Generate AI summary
	geminiService, err := NewGeminiService()
	if err != nil {
		log.Printf("Failed to create Gemini service: %v", err)
		// Return data without AI summary
		response := map[string]interface{}{
			"source":  source,
			"summary": fmt.Sprintf("**CVE:** %s\n\n**Description:** %s\n\n**Severity:** %s (%.1f)", 
				cveData.ID, cveData.Description, cveData.Severity, cveData.Score),
		}
		if err := writeJSON(w, http.StatusOK, response); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
		return
	}

	summary, err := geminiService.GenerateSummary(cveData)
	if err != nil {
		log.Printf("Failed to generate AI summary: %v", err)
		summary = fmt.Sprintf("**CVE:** %s\n\n**Description:** %s\n\n**Severity:** %s (%.1f)", 
			cveData.ID, cveData.Description, cveData.Severity, cveData.Score)
	}

	response := map[string]interface{}{
		"source":  source,
		"summary": summary,
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./ui/html/index.html")
}

func health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"healthy"}`)
}