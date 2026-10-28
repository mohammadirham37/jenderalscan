package main

import (
	"testing"

	"jenderalscan/internal/models"
)

func TestAppEndToEndWithSandboxAndExports(t *testing.T) {
	app, err := NewApp(":memory:")
	if err != nil {
		t.Fatalf("NewApp failed: %v", err)
	}
	defer app.shutdown(nil)

	sandboxURL, err := app.StartSandboxTarget()
	if err != nil || sandboxURL == "" {
		t.Fatalf("StartSandboxTarget failed: %v", err)
	}

	res, err := app.StartScan(models.ScanRequest{
		TargetURL:         sandboxURL,
		Profile:           models.ProfileFull,
		AuthorizedConfirm: true,
		AuthorizationNote: "Automated E2E Sandbox Verification",
	})
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}
	if res.Summary.Total < 5 {
		t.Fatalf("expected at least 5 findings on sandbox target, got %d", res.Summary.Total)
	}

	// Test exporting all 4 formats (JSON, Markdown, HTML, PDF)
	for _, fmtName := range []string{"json", "md", "html", "pdf"} {
		payload, err := app.ExportReport(res.ID, fmtName)
		if err != nil {
			t.Fatalf("ExportReport(%s) failed: %v", fmtName, err)
		}
		if payload.ContentBase64 == "" || payload.Filename == "" {
			t.Fatalf("ExportReport(%s) returned empty content", fmtName)
		}
	}

	// Test Audit Log creation
	logs, err := app.ListAuditLogs()
	if err != nil || len(logs) != 1 {
		t.Fatalf("expected 1 audit log entry, got %d (err=%v)", len(logs), err)
	}
}
