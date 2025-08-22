package models

import (
	"testing"

	"vuln_analyzer/internal/errors"
)

func TestValidateCVEID(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        string
		wantErr     error
		description string
	}{
		{
			name:        "valid_cve_id",
			input:       "CVE-2023-1234",
			want:        "CVE-2023-1234",
			wantErr:     nil,
			description: "should accept properly formatted CVE ID",
		},
		{
			name:        "valid_cve_id_lowercase",
			input:       "cve-2023-1234",
			want:        "CVE-2023-1234",
			wantErr:     nil,
			description: "should normalize lowercase CVE ID to uppercase",
		},
		{
			name:        "valid_cve_id_with_spaces",
			input:       "  CVE-2023-1234  ",
			want:        "CVE-2023-1234",
			wantErr:     nil,
			description: "should trim whitespace from CVE ID",
		},
		{
			name:        "valid_cve_id_five_digits",
			input:       "CVE-2023-12345",
			want:        "CVE-2023-12345",
			wantErr:     nil,
			description: "should accept CVE ID with 5-digit sequence number",
		},
		{
			name:        "valid_cve_id_six_digits",
			input:       "CVE-2023-123456",
			want:        "CVE-2023-123456",
			wantErr:     nil,
			description: "should accept CVE ID with 6-digit sequence number",
		},
		{
			name:        "empty_cve_id",
			input:       "",
			want:        "",
			wantErr:     errors.ErrEmptyCVEID,
			description: "should return error for empty CVE ID",
		},
		{
			name:        "whitespace_only",
			input:       "   ",
			want:        "",
			wantErr:     errors.ErrInvalidCVEID,
			description: "should return error for whitespace-only input",
		},
		{
			name:        "invalid_format_no_cve_prefix",
			input:       "2023-1234",
			want:        "",
			wantErr:     errors.ErrInvalidCVEID,
			description: "should return error for missing CVE prefix",
		},
		{
			name:        "invalid_format_wrong_year",
			input:       "CVE-23-1234",
			want:        "",
			wantErr:     errors.ErrInvalidCVEID,
			description: "should return error for 2-digit year",
		},
		{
			name:        "invalid_format_three_digit_sequence",
			input:       "CVE-2023-123",
			want:        "",
			wantErr:     errors.ErrInvalidCVEID,
			description: "should return error for 3-digit sequence number",
		},
		{
			name:        "invalid_format_no_dashes",
			input:       "CVE20231234",
			want:        "",
			wantErr:     errors.ErrInvalidCVEID,
			description: "should return error for missing dashes",
		},
		{
			name:        "invalid_format_extra_parts",
			input:       "CVE-2023-1234-extra",
			want:        "",
			wantErr:     errors.ErrInvalidCVEID,
			description: "should return error for extra parts",
		},
		{
			name:        "invalid_format_letters_in_year",
			input:       "CVE-202a-1234",
			want:        "",
			wantErr:     errors.ErrInvalidCVEID,
			description: "should return error for letters in year",
		},
		{
			name:        "invalid_format_letters_in_sequence",
			input:       "CVE-2023-12a4",
			want:        "",
			wantErr:     errors.ErrInvalidCVEID,
			description: "should return error for letters in sequence number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateCVEID(tt.input)
			
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ValidateCVEID() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if err != tt.wantErr {
					t.Errorf("ValidateCVEID() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			} else {
				if err != nil {
					t.Errorf("ValidateCVEID() unexpected error = %v", err)
					return
				}
			}
			
			if got != tt.want {
				t.Errorf("ValidateCVEID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCVEIDRegex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid_pattern",
			input: "CVE-2023-1234",
			want:  true,
		},
		{
			name:  "valid_pattern_long_sequence",
			input: "CVE-2023-123456789",
			want:  true,
		},
		{
			name:  "invalid_short_sequence",
			input: "CVE-2023-123",
			want:  false,
		},
		{
			name:  "invalid_no_prefix",
			input: "2023-1234",
			want:  false,
		},
		{
			name:  "invalid_wrong_prefix",
			input: "CWE-2023-1234",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CVEIDRegex.MatchString(tt.input)
			if got != tt.want {
				t.Errorf("CVEIDRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}