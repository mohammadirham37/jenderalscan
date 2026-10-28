package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"jenderalscan/internal/models"
)

func TestExportJSONHTMLAndPDF(t *testing.T) {
	scan := &models.ScanResult{
		ID:                "scan-report-1",
		TargetURL:         "https://target.example.id/",
		NormalizedHost:    "target.example.id",
		Profile:           models.ProfileQuick,
		Status:            "completed",
		AuthorizedConfirm: true,
		AuthorizationNote: "Audit Internal #42",
		ScopeLocked:       true,
		StartedAt:         time.Now().Add(-5 * time.Second),
		CompletedAt:       time.Now(),
		DurationMs:        4850,
		RequestsSent:      12,
		Summary:           models.SeveritySummary{High: 1, Medium: 1, Total: 2},
		Technologies: []models.DetectedTech{
			{Name: "nginx", Category: "Web Server", Version: "1.18.0", Source: "Header Server"},
		},
		Findings: []models.Finding{
			{
				ID:               "f-1",
				ScanID:           "scan-report-1",
				Module:           models.ModulePaths,
				RuleID:           "PATH-ENV-FILE",
				Title:            "File .env Terekspos",
				TitleEN:          "Exposed .env File",
				Severity:         models.SeverityHigh,
				Confidence:       models.ConfidenceHigh,
				Description:      "File .env dapat diakses publik.",
				DescriptionEN:    "The .env file is publicly accessible.",
				Impact:           "Kebocoran kredensial database.",
				ImpactEN:         "Database credential exposure.",
				Recommendation:   "Blokir akses dotfile.",
				RecommendationEN: "Deny dotfile access.",
				Evidence:         "GET /.env -> HTTP 200\nDB_PASSWORD=***",
				CWE:              "CWE-215",
				OWASP:            "OWASP A05:2021",
			},
		},
	}

	// 1. JSON
	jsonBytes, err := ExportJSON(scan)
	if err != nil || !strings.Contains(string(jsonBytes), "PATH-ENV-FILE") {
		t.Fatalf("ExportJSON failed: err=%v", err)
	}

	// 1b. Markdown (ID & EN)
	mdID, err := ExportMarkdown(scan, "id")
	if err != nil || !strings.Contains(string(mdID), "# JenderalScan") || !strings.Contains(string(mdID), "File .env Terekspos") {
		t.Fatalf("ExportMarkdown (id) failed: err=%v", err)
	}
	mdEN, err := ExportMarkdown(scan, "en")
	if err != nil || !strings.Contains(string(mdEN), "Exposed .env File") {
		t.Fatalf("ExportMarkdown (en) failed: err=%v", err)
	}

	// 2. HTML (ID & EN)
	htmlID, err := ExportHTML(scan, "id")
	if err != nil || !strings.Contains(string(htmlID), "File .env Terekspos") {
		t.Fatalf("ExportHTML (id) failed: err=%v", err)
	}
	htmlEN, err := ExportHTML(scan, "en")
	if err != nil || !strings.Contains(string(htmlEN), "Exposed .env File") {
		t.Fatalf("ExportHTML (en) failed: err=%v", err)
	}

	// 3. PDF
	pdfBytes, err := ExportPDF(scan, "id")
	if err != nil {
		t.Fatalf("ExportPDF failed: %v", err)
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4")) || !bytes.Contains(pdfBytes, []byte("%%EOF")) {
		t.Fatalf("ExportPDF did not produce valid PDF 1.4 header/trailer")
	}
}
