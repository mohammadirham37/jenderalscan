package storage

import (
	"testing"
	"time"

	"jenderalscan/internal/models"
)

func TestStoreSaveLoadAndDiff(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	// 1. Test Settings persistence
	cfg, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}
	if cfg.MaxWorkers != 5 {
		t.Fatalf("expected default MaxWorkers=5, got %d", cfg.MaxWorkers)
	}
	cfg.MaxWorkers = 8
	cfg.RateLimitRPS = 20
	if err := store.SaveSettings(cfg); err != nil {
		t.Fatalf("SaveSettings failed: %v", err)
	}
	loadedCfg, err := store.GetSettings()
	if err != nil || loadedCfg.MaxWorkers != 8 || loadedCfg.RateLimitRPS != 20 {
		t.Fatalf("unexpected loaded settings: %+v, err=%v", loadedCfg, err)
	}

	// 2. Save first scan
	scan1 := &models.ScanResult{
		ID:                "scan-1",
		TargetURL:         "https://example.com/",
		NormalizedHost:    "example.com",
		Profile:           models.ProfileQuick,
		Status:            "completed",
		AuthorizedConfirm: true,
		ScopeLocked:       true,
		StartedAt:         time.Now().Add(-10 * time.Minute),
		CompletedAt:       time.Now().Add(-9 * time.Minute),
		DurationMs:        1200,
		Findings: []models.Finding{
			{
				ID:          "f-1",
				ScanID:      "scan-1",
				Module:      models.ModuleHeaders,
				RuleID:      "HDR-HSTS-MISSING",
				Fingerprint: "fp-hsts",
				Title:       "HSTS Missing",
				Severity:    models.SeverityMedium,
				Confidence:  models.ConfidenceHigh,
				CreatedAt:   time.Now(),
			},
			{
				ID:          "f-2",
				ScanID:      "scan-1",
				Module:      models.ModuleHeaders,
				RuleID:      "HDR-CSP-MISSING",
				Fingerprint: "fp-csp",
				Title:       "CSP Missing",
				Severity:    models.SeverityMedium,
				Confidence:  models.ConfidenceHigh,
				CreatedAt:   time.Now(),
			},
		},
		Summary: models.SeveritySummary{Medium: 2, Total: 2},
	}
	if err := store.ComputeDiffAndDecorate(scan1); err != nil {
		t.Fatalf("ComputeDiffAndDecorate scan1: %v", err)
	}
	if err := store.SaveScan(scan1); err != nil {
		t.Fatalf("SaveScan scan1: %v", err)
	}

	// 3. Save second scan on same host where fp-hsts is fixed, fp-csp is recurring, and fp-xfo is new
	scan2 := &models.ScanResult{
		ID:                "scan-2",
		TargetURL:         "https://example.com/",
		NormalizedHost:    "example.com",
		Profile:           models.ProfileQuick,
		Status:            "completed",
		AuthorizedConfirm: true,
		ScopeLocked:       true,
		StartedAt:         time.Now().Add(-1 * time.Minute),
		CompletedAt:       time.Now(),
		DurationMs:        950,
		Findings: []models.Finding{
			{
				ID:          "f-3",
				ScanID:      "scan-2",
				Module:      models.ModuleHeaders,
				RuleID:      "HDR-CSP-MISSING",
				Fingerprint: "fp-csp",
				Title:       "CSP Missing",
				Severity:    models.SeverityMedium,
				Confidence:  models.ConfidenceHigh,
				CreatedAt:   time.Now(),
			},
			{
				ID:          "f-4",
				ScanID:      "scan-2",
				Module:      models.ModuleHeaders,
				RuleID:      "HDR-XFO-MISSING",
				Fingerprint: "fp-xfo",
				Title:       "XFO Missing",
				Severity:    models.SeverityMedium,
				Confidence:  models.ConfidenceHigh,
				CreatedAt:   time.Now(),
			},
		},
		Summary: models.SeveritySummary{Medium: 2, Total: 2},
	}

	if err := store.ComputeDiffAndDecorate(scan2); err != nil {
		t.Fatalf("ComputeDiffAndDecorate scan2: %v", err)
	}
	if scan2.Diff == nil {
		t.Fatal("expected non-nil Diff on scan2")
	}
	if scan2.Diff.NewCount != 1 || scan2.Diff.RecurringCount != 1 || scan2.Diff.FixedCount != 1 {
		t.Fatalf("unexpected diff counts: %+v", scan2.Diff)
	}
	if err := store.SaveScan(scan2); err != nil {
		t.Fatalf("SaveScan scan2: %v", err)
	}

	// 4. Test Audit Log
	if err := store.RecordAuditLog(models.AuditLogEntry{
		ScanID:            "scan-2",
		Timestamp:         time.Now(),
		TargetURL:         "https://example.com/",
		NormalizedHost:    "example.com",
		Profile:           "Quick",
		ModulesExecuted:   "headers",
		AuthorizedConfirm: true,
		RateLimitRPS:      10,
		Status:            "completed",
		TotalFindings:     2,
	}); err != nil {
		t.Fatalf("RecordAuditLog failed: %v", err)
	}

	logs, err := store.ListAuditLogs()
	if err != nil || len(logs) != 1 {
		t.Fatalf("expected 1 audit log, got %d (err=%v)", len(logs), err)
	}
}
