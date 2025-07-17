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

	// Try NVD first
	nvdService, err := NewNVDService()
	if err == nil {
		if cveData, err := nvdService.Fetch(req.CVE); err == nil {
			log.Printf("Successfully fetched %s from NVD", req.CVE)
			if err := writeJSON(w, http.StatusOK, cveData); err != nil {
				log.Printf("Failed to write response: %v", err)
			}
			return
		} else {
			log.Printf("NVD fetch failed for %s: %v", req.CVE, err)
		}
	}

	// Fallback to OSV
	log.Printf("Trying OSV fallback for %s", req.CVE)
	osvService := NewOSVService()
	cveData, err := osvService.Fetch(req.CVE)
	if err != nil {
		log.Printf("OSV fetch failed for %s: %v", req.CVE, err)
		writeErrorResponse(w, http.StatusNotFound, fmt.Sprintf("CVE %s not found", req.CVE), req.CVE)
		return
	}

	log.Printf("Successfully fetched %s from OSV", req.CVE)
	if err := writeJSON(w, http.StatusOK, cveData); err != nil {
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