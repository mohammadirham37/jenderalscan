package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"jenderalscan/internal/models"

	_ "modernc.org/sqlite"
)

// Store manages local SQLite persistence for scans, findings, settings, and audit logs.
type Store struct {
	db   *sql.DB
	path string
	mu   sync.RWMutex
}

// DefaultDBPath returns the platform-appropriate local application data database path.
func DefaultDBPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = os.TempDir()
	}
	appDir := filepath.Join(configDir, "JenderalScan")
	if err := os.MkdirAll(appDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create app data dir: %w", err)
	}
	return filepath.Join(appDir, "jenderalscan.db"), nil
}

// NewStore opens and initializes the SQLite database at dbPath.
func NewStore(dbPath string) (*Store, error) {
	if dbPath == "" {
		var err error
		dbPath, err = DefaultDBPath()
		if err != nil {
			return nil, err
		}
	}
	if dbPath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
			return nil, fmt.Errorf("mkdir db dir: %w", err)
		}
	}

	dsn := dbPath
	if dbPath != ":memory:" {
		dsn = fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", dbPath)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{
		db:   db,
		path: dbPath,
	}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	return s, nil
}

// Close closes the underlying SQLite connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		target_url TEXT NOT NULL,
		normalized_host TEXT NOT NULL,
		profile TEXT NOT NULL,
		status TEXT NOT NULL,
		authorized_confirm INTEGER NOT NULL,
		authorization_note TEXT NOT NULL,
		scope_locked INTEGER NOT NULL,
		started_at DATETIME NOT NULL,
		completed_at DATETIME NOT NULL,
		duration_ms INTEGER NOT NULL,
		requests_sent INTEGER NOT NULL,
		error_message TEXT NOT NULL,
		module_statuses_json TEXT NOT NULL,
		technologies_json TEXT NOT NULL,
		summary_json TEXT NOT NULL,
		diff_json TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(normalized_host, started_at DESC);
	CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		module TEXT NOT NULL,
		rule_id TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		title TEXT NOT NULL,
		title_en TEXT NOT NULL,
		severity TEXT NOT NULL,
		confidence TEXT NOT NULL,
		description TEXT NOT NULL,
		description_en TEXT NOT NULL,
		impact TEXT NOT NULL,
		impact_en TEXT NOT NULL,
		recommendation TEXT NOT NULL,
		recommendation_en TEXT NOT NULL,
		evidence TEXT NOT NULL,
		target_url TEXT NOT NULL,
		references_json TEXT NOT NULL,
		cwe TEXT NOT NULL,
		owasp TEXT NOT NULL,
		cvss REAL NOT NULL,
		diff_status TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		target_url TEXT NOT NULL,
		normalized_host TEXT NOT NULL,
		profile TEXT NOT NULL,
		modules_executed TEXT NOT NULL,
		authorized_confirm INTEGER NOT NULL,
		authorization_note TEXT NOT NULL,
		rate_limit_rps INTEGER NOT NULL,
		status TEXT NOT NULL,
		duration_ms INTEGER NOT NULL,
		total_findings INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);

	CREATE TABLE IF NOT EXISTS custom_cves (
		cve_id TEXT PRIMARY KEY,
		entry_json TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

// GetSettings loads AppSettings from SQLite or returns DefaultSettings if not yet saved.
func (s *Store) GetSettings() (models.AppSettings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	defaults := models.DefaultSettings()
	var raw string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'app_settings'`).Scan(&raw)
	if err == sql.ErrNoRows {
		return defaults, nil
	}
	if err != nil {
		return defaults, err
	}

	var cfg models.AppSettings
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return defaults, nil
	}
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = defaults.MaxWorkers
	}
	if cfg.RateLimitRPS <= 0 {
		cfg.RateLimitRPS = defaults.RateLimitRPS
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = defaults.TimeoutSeconds
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaults.UserAgent
	}
	if cfg.Language == "" {
		cfg.Language = defaults.Language
	}
	if cfg.Theme == "" {
		cfg.Theme = defaults.Theme
	}
	if cfg.CustomHeaders == nil {
		cfg.CustomHeaders = map[string]string{}
	}
	return cfg, nil
}

// SaveSettings persists AppSettings to SQLite.
func (s *Store) SaveSettings(cfg models.AppSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO settings (key, value, updated_at)
		VALUES ('app_settings', ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, string(data), time.Now().UTC())
	return err
}

// ComputeDiffAndDecorate compares scan findings against the most recent completed scan for the same host.
func (s *Store) ComputeDiffAndDecorate(scan *models.ScanResult) error {
	prevScan, err := s.GetLatestCompletedScanForHost(scan.NormalizedHost, scan.ID)
	if err != nil || prevScan == nil {
		for i := range scan.Findings {
			scan.Findings[i].DiffStatus = models.DiffNew
		}
		scan.Diff = &models.ScanDiff{
			NewCount: len(scan.Findings),
		}
		return nil
	}

	prevByFP := make(map[string]models.Finding, len(prevScan.Findings))
	for _, f := range prevScan.Findings {
		prevByFP[f.Fingerprint] = f
	}

	currentFPs := make(map[string]bool, len(scan.Findings))
	newCount := 0
	recurringCount := 0

	for i := range scan.Findings {
		fp := scan.Findings[i].Fingerprint
		currentFPs[fp] = true
		if _, existed := prevByFP[fp]; existed {
			scan.Findings[i].DiffStatus = models.DiffRecurring
			recurringCount++
		} else {
			scan.Findings[i].DiffStatus = models.DiffNew
			newCount++
		}
	}

	var fixedFindings []models.Finding
	for fp, oldFinding := range prevByFP {
		if !currentFPs[fp] {
			oldFinding.DiffStatus = models.DiffFixed
			fixedFindings = append(fixedFindings, oldFinding)
		}
	}

	scan.Diff = &models.ScanDiff{
		PreviousScanID: prevScan.ID,
		PreviousDate:   prevScan.StartedAt,
		NewCount:       newCount,
		RecurringCount: recurringCount,
		FixedCount:     len(fixedFindings),
		FixedFindings:  fixedFindings,
	}
	return nil
}

// GetLatestCompletedScanForHost retrieves the latest completed scan for a given host excluding excludeScanID.
func (s *Store) GetLatestCompletedScanForHost(normalizedHost, excludeScanID string) (*models.ScanResult, error) {
	s.mu.RLock()
	var scanID string
	err := s.db.QueryRow(`
		SELECT id FROM scans
		WHERE normalized_host = ? AND id != ? AND status = 'completed'
		ORDER BY started_at DESC
		LIMIT 1
	`, normalizedHost, excludeScanID).Scan(&scanID)
	s.mu.RUnlock()

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetScan(scanID)
}

// SaveScan stores or updates a ScanResult and all its findings in a transaction.
func (s *Store) SaveScan(scan *models.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	modJSON, _ := json.Marshal(scan.ModuleStatuses)
	techJSON, _ := json.Marshal(scan.Technologies)
	sumJSON, _ := json.Marshal(scan.Summary)
	diffJSON, _ := json.Marshal(scan.Diff)

	authInt := 0
	if scan.AuthorizedConfirm {
		authInt = 1
	}
	scopeInt := 0
	if scan.ScopeLocked {
		scopeInt = 1
	}

	_, err = tx.Exec(`
		INSERT INTO scans (
			id, target_url, normalized_host, profile, status,
			authorized_confirm, authorization_note, scope_locked,
			started_at, completed_at, duration_ms, requests_sent,
			error_message, module_statuses_json, technologies_json,
			summary_json, diff_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			status = excluded.status,
			completed_at = excluded.completed_at,
			duration_ms = excluded.duration_ms,
			requests_sent = excluded.requests_sent,
			error_message = excluded.error_message,
			module_statuses_json = excluded.module_statuses_json,
			technologies_json = excluded.technologies_json,
			summary_json = excluded.summary_json,
			diff_json = excluded.diff_json
	`,
		scan.ID, scan.TargetURL, scan.NormalizedHost, string(scan.Profile), scan.Status,
		authInt, scan.AuthorizationNote, scopeInt,
		scan.StartedAt.UTC(), scan.CompletedAt.UTC(), scan.DurationMs, scan.RequestsSent,
		scan.ErrorMessage, string(modJSON), string(techJSON),
		string(sumJSON), string(diffJSON),
	)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM findings WHERE scan_id = ?`, scan.ID); err != nil {
		return fmt.Errorf("clear findings: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO findings (
			id, scan_id, module, rule_id, fingerprint,
			title, title_en, severity, confidence,
			description, description_en, impact, impact_en,
			recommendation, recommendation_en, evidence, target_url,
			references_json, cwe, owasp, cvss, diff_status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range scan.Findings {
		refsJSON, _ := json.Marshal(f.References)
		_, err := stmt.Exec(
			f.ID, scan.ID, string(f.Module), f.RuleID, f.Fingerprint,
			f.Title, f.TitleEN, string(f.Severity), string(f.Confidence),
			f.Description, f.DescriptionEN, f.Impact, f.ImpactEN,
			f.Recommendation, f.RecommendationEN, f.Evidence, f.TargetURL,
			string(refsJSON), f.CWE, f.OWASP, f.CVSS, string(f.DiffStatus), f.CreatedAt.UTC(),
		)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", f.ID, err)
		}
	}

	return tx.Commit()
}

// GetScan retrieves a complete ScanResult including findings by ID.
func (s *Store) GetScan(scanID string) (*models.ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var scan models.ScanResult
	var profileStr string
	var authInt, scopeInt int
	var modJSON, techJSON, sumJSON, diffJSON string

	err := s.db.QueryRow(`
		SELECT
			id, target_url, normalized_host, profile, status,
			authorized_confirm, authorization_note, scope_locked,
			started_at, completed_at, duration_ms, requests_sent,
			error_message, module_statuses_json, technologies_json,
			summary_json, diff_json
		FROM scans WHERE id = ?
	`, scanID).Scan(
		&scan.ID, &scan.TargetURL, &scan.NormalizedHost, &profileStr, &scan.Status,
		&authInt, &scan.AuthorizationNote, &scopeInt,
		&scan.StartedAt, &scan.CompletedAt, &scan.DurationMs, &scan.RequestsSent,
		&scan.ErrorMessage, &modJSON, &techJSON, &sumJSON, &diffJSON,
	)
	if err != nil {
		return nil, err
	}

	scan.Profile = models.ScanProfile(profileStr)
	scan.AuthorizedConfirm = authInt == 1
	scan.ScopeLocked = scopeInt == 1
	_ = json.Unmarshal([]byte(modJSON), &scan.ModuleStatuses)
	_ = json.Unmarshal([]byte(techJSON), &scan.Technologies)
	_ = json.Unmarshal([]byte(sumJSON), &scan.Summary)
	if diffJSON != "" && diffJSON != "null" {
		var d models.ScanDiff
		if err := json.Unmarshal([]byte(diffJSON), &d); err == nil {
			scan.Diff = &d
		}
	}

	rows, err := s.db.Query(`
		SELECT
			id, scan_id, module, rule_id, fingerprint,
			title, title_en, severity, confidence,
			description, description_en, impact, impact_en,
			recommendation, recommendation_en, evidence, target_url,
			references_json, cwe, owasp, cvss, diff_status, created_at
		FROM findings WHERE scan_id = ?
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scan.Findings = []models.Finding{}
	for rows.Next() {
		var f models.Finding
		var modStr, sevStr, confStr, refsJSON, diffStr string
		if err := rows.Scan(
			&f.ID, &f.ScanID, &modStr, &f.RuleID, &f.Fingerprint,
			&f.Title, &f.TitleEN, &sevStr, &confStr,
			&f.Description, &f.DescriptionEN, &f.Impact, &f.ImpactEN,
			&f.Recommendation, &f.RecommendationEN, &f.Evidence, &f.TargetURL,
			&refsJSON, &f.CWE, &f.OWASP, &f.CVSS, &diffStr, &f.CreatedAt,
		); err != nil {
			return nil, err
		}
		f.Module = models.ModuleID(modStr)
		f.Severity = models.Severity(sevStr)
		f.Confidence = models.Confidence(confStr)
		f.DiffStatus = models.DiffStatus(diffStr)
		_ = json.Unmarshal([]byte(refsJSON), &f.References)
		scan.Findings = append(scan.Findings, f)
	}

	return &scan, nil
}

// ListScans returns all saved scans ordered by most recent first (summary metadata).
func (s *Store) ListScans() ([]models.ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT
			id, target_url, normalized_host, profile, status,
			authorized_confirm, authorization_note, scope_locked,
			started_at, completed_at, duration_ms, requests_sent,
			error_message, module_statuses_json, technologies_json,
			summary_json, diff_json
		FROM scans
		ORDER BY started_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.ScanResult
	for rows.Next() {
		var scan models.ScanResult
		var profileStr string
		var authInt, scopeInt int
		var modJSON, techJSON, sumJSON, diffJSON string
		if err := rows.Scan(
			&scan.ID, &scan.TargetURL, &scan.NormalizedHost, &profileStr, &scan.Status,
			&authInt, &scan.AuthorizationNote, &scopeInt,
			&scan.StartedAt, &scan.CompletedAt, &scan.DurationMs, &scan.RequestsSent,
			&scan.ErrorMessage, &modJSON, &techJSON, &sumJSON, &diffJSON,
		); err != nil {
			return nil, err
		}
		scan.Profile = models.ScanProfile(profileStr)
		scan.AuthorizedConfirm = authInt == 1
		scan.ScopeLocked = scopeInt == 1
		_ = json.Unmarshal([]byte(modJSON), &scan.ModuleStatuses)
		_ = json.Unmarshal([]byte(techJSON), &scan.Technologies)
		_ = json.Unmarshal([]byte(sumJSON), &scan.Summary)
		if diffJSON != "" && diffJSON != "null" {
			var d models.ScanDiff
			if err := json.Unmarshal([]byte(diffJSON), &d); err == nil {
				scan.Diff = &d
			}
		}
		results = append(results, scan)
	}
	if results == nil {
		results = []models.ScanResult{}
	}
	return results, nil
}

// DeleteScan removes a single scan and its findings.
func (s *Store) DeleteScan(scanID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM findings WHERE scan_id = ?`, scanID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM scans WHERE id = ?`, scanID); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearHistory removes all scan records and findings while preserving audit logs or optionally clearing all.
func (s *Store) ClearHistory() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM findings`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM scans`); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordAuditLog writes or updates an entry in the audit log table.
func (s *Store) RecordAuditLog(entry models.AuditLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	authInt := 0
	if entry.AuthorizedConfirm {
		authInt = 1
	}

	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM audit_logs WHERE scan_id = ?`, entry.ScanID).Scan(&existingID)
	if err == sql.ErrNoRows {
		_, err = s.db.Exec(`
			INSERT INTO audit_logs (
				scan_id, timestamp, target_url, normalized_host,
				profile, modules_executed, authorized_confirm,
				authorization_note, rate_limit_rps, status,
				duration_ms, total_findings
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			entry.ScanID, entry.Timestamp.UTC(), entry.TargetURL, entry.NormalizedHost,
			entry.Profile, entry.ModulesExecuted, authInt,
			entry.AuthorizationNote, entry.RateLimitRPS, entry.Status,
			entry.DurationMs, entry.TotalFindings,
		)
		return err
	}
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		UPDATE audit_logs
		SET status = ?, duration_ms = ?, total_findings = ?
		WHERE id = ?
	`, entry.Status, entry.DurationMs, entry.TotalFindings, existingID)
	return err
}

// ListAuditLogs returns the audit trail of scans ordered by newest first.
func (s *Store) ListAuditLogs() ([]models.AuditLogEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT
			id, scan_id, timestamp, target_url, normalized_host,
			profile, modules_executed, authorized_confirm,
			authorization_note, rate_limit_rps, status,
			duration_ms, total_findings
		FROM audit_logs
		ORDER BY timestamp DESC
		LIMIT 200
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.AuditLogEntry
	for rows.Next() {
		var l models.AuditLogEntry
		var authInt int
		if err := rows.Scan(
			&l.ID, &l.ScanID, &l.Timestamp, &l.TargetURL, &l.NormalizedHost,
			&l.Profile, &l.ModulesExecuted, &authInt,
			&l.AuthorizationNote, &l.RateLimitRPS, &l.Status,
			&l.DurationMs, &l.TotalFindings,
		); err != nil {
			return nil, err
		}
		l.AuthorizedConfirm = authInt == 1
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []models.AuditLogEntry{}
	}
	return logs, nil
}

// SaveCustomCVEs stores user-updated or imported CVE entries into SQLite.
func (s *Store) SaveCustomCVEs(entries []models.CVEEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT INTO custom_cves (cve_id, entry_json, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET entry_json = excluded.entry_json, updated_at = excluded.updated_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for _, e := range entries {
		if e.CVEID == "" {
			continue
		}
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		if _, err := stmt.Exec(e.CVEID, string(raw), now); err != nil {
			return err
		}
	}

	_, _ = tx.Exec(`
		INSERT INTO settings (key, value, updated_at)
		VALUES ('cve_last_updated', ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, now.Format(time.RFC3339), now)

	return tx.Commit()
}

// LoadCustomCVEs returns custom/updated CVE entries stored in SQLite and the last update timestamp.
func (s *Store) LoadCustomCVEs() ([]models.CVEEntry, *time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT entry_json FROM custom_cves`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var list []models.CVEEntry
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var e models.CVEEntry
		if err := json.Unmarshal([]byte(raw), &e); err == nil {
			list = append(list, e)
		}
	}

	var tsStr string
	var lastUpdated *time.Time
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'cve_last_updated'`).Scan(&tsStr); err == nil {
		if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
			lastUpdated = &t
		}
	}
	return list, lastUpdated, nil
}
