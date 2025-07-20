package http

import (
	"fmt"
	"regexp"
	"strings"
)

// CVERequest represents a request for CVE analysis.
type CVERequest struct {
	CVE string `json:"cve" validate:"required,cve"`
}

// CVEResponse represents the response for CVE analysis.
type CVEResponse struct {
	Source  string `json:"source"`
	Summary string `json:"summary"`
}

// CVE validation regex
var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Validate validates the CVE request.
func (r *CVERequest) Validate() error {
	if r.CVE == "" {
		return fmt.Errorf("CVE ID is required")
	}

	// Normalize CVE ID
	r.CVE = strings.ToUpper(strings.TrimSpace(r.CVE))
	
	// Validate format
	if !cveRegex.MatchString(r.CVE) {
		return fmt.Errorf("invalid CVE ID format: must match CVE-YYYY-NNNN pattern")
	}

	// Additional length check
	if len(r.CVE) > 32 {
		return fmt.Errorf("CVE ID too long: maximum 32 characters")
	}

	return nil
}