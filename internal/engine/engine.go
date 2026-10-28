package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"jenderalscan/internal/models"
	"jenderalscan/internal/storage"

	"github.com/google/uuid"
)

// ScannerModule is implemented by each independent security surface scanner module.
type ScannerModule interface {
	ID() models.ModuleID
	Name() string
	Run(ctx context.Context, scanCtx *ScanContext) ([]models.Finding, error)
}

// ScanContext holds shared state and safe primitives for modules running within a scan.
type ScanContext struct {
	ScanID   string
	Target   *TargetScope
	Client   *ScopedClient
	Baseline *BaselineResponse
	Settings models.AppSettings
	Profile  models.ScanProfile

	techMu       sync.RWMutex
	technologies []models.DetectedTech
}

// AddTechnology records a detected technology in a thread-safe manner (deduplicated by Name+Version).
func (sc *ScanContext) AddTechnology(tech models.DetectedTech) {
	sc.techMu.Lock()
	defer sc.techMu.Unlock()

	key := strings.ToLower(tech.Name + "|" + tech.Version)
	for i, existing := range sc.technologies {
		exKey := strings.ToLower(existing.Name + "|" + existing.Version)
		if exKey == key {
			if existing.Language == "" && tech.Language != "" {
				sc.technologies[i].Language = tech.Language
			}
			return
		}
		// If same product name and new one has a concrete version while old one was empty, upgrade it
		if strings.EqualFold(existing.Name, tech.Name) && existing.Version == "" && tech.Version != "" {
			if tech.Language == "" {
				tech.Language = existing.Language
			}
			sc.technologies[i] = tech
			return
		}
		if strings.EqualFold(existing.Name, tech.Name) && existing.Version != "" && tech.Version == "" {
			return
		}
	}
	sc.technologies = append(sc.technologies, tech)
}

// AttachTechCVE appends a CVE identifier to a detected technology's PotentialCVEs list.
func (sc *ScanContext) AttachTechCVE(techName string, cveBadge string) {
	sc.techMu.Lock()
	defer sc.techMu.Unlock()

	for i := range sc.technologies {
		if strings.EqualFold(sc.technologies[i].Name, techName) {
			exists := false
			for _, existing := range sc.technologies[i].PotentialCVEs {
				if existing == cveBadge {
					exists = true
					break
				}
			}
			if !exists {
				sc.technologies[i].PotentialCVEs = append(sc.technologies[i].PotentialCVEs, cveBadge)
			}
		}
	}
}

// GetTechnologies returns a copy of all detected technologies so far.
func (sc *ScanContext) GetTechnologies() []models.DetectedTech {
	sc.techMu.RLock()
	defer sc.techMu.RUnlock()

	out := make([]models.DetectedTech, len(sc.technologies))
	copy(out, sc.technologies)
	return out
}

// ProgressCallback is invoked whenever scan progress or module state changes.
type ProgressCallback func(event models.ScanProgressEvent)

// Engine orchestrates scanner modules over a worker pool with rate limiting and persistence.
type Engine struct {
	store    *storage.Store
	modules  map[models.ModuleID]ScannerModule
	order    []models.ModuleID
	activeMu sync.Mutex
	active   map[string]context.CancelFunc
}

// NewEngine creates a new Scan Engine with a backing store.
func NewEngine(store *storage.Store) *Engine {
	return &Engine{
		store:   store,
		modules: make(map[models.ModuleID]ScannerModule),
		active:  make(map[string]context.CancelFunc),
	}
}

// RegisterModule registers a ScannerModule implementation into the engine.
func (e *Engine) RegisterModule(m ScannerModule) {
	e.modules[m.ID()] = m
	e.order = append(e.order, m.ID())
}

// CancelScan cancels a running scan by ID.
func (e *Engine) CancelScan(scanID string) bool {
	e.activeMu.Lock()
	defer e.activeMu.Unlock()

	if cancel, ok := e.active[scanID]; ok {
		cancel()
		return true
	}
	return false
}

// ResolveProfileModules returns the list of module IDs to execute for the given ScanRequest.
func ResolveProfileModules(req models.ScanRequest) []models.ModuleID {
	switch req.Profile {
	case models.ProfileQuick:
		return []models.ModuleID{
			models.ModuleHeaders,
			models.ModuleTLS,
			models.ModuleCookies,
			models.ModulePaths,
			models.ModuleFingerprint,
			models.ModuleCVE,
		}
	case models.ProfileFull:
		return []models.ModuleID{
			models.ModuleHeaders,
			models.ModuleTLS,
			models.ModuleCookies,
			models.ModulePaths,
			models.ModuleFingerprint,
			models.ModuleCVE,
			models.ModuleCORS,
			models.ModuleDisclosure,
			models.ModuleDNS,
			models.ModulePorts,
		}
	case models.ProfileCustom:
		if len(req.Modules) > 0 {
			return req.Modules
		}
		return []models.ModuleID{
			models.ModuleHeaders,
			models.ModuleTLS,
			models.ModuleCookies,
			models.ModulePaths,
			models.ModuleFingerprint,
		}
	default:
		return []models.ModuleID{
			models.ModuleHeaders,
			models.ModuleTLS,
			models.ModuleCookies,
			models.ModulePaths,
			models.ModuleFingerprint,
		}
	}
}

// ExecuteScan runs a complete scan synchronously (call in a goroutine for async UI) and emits real-time progress events.
func (e *Engine) ExecuteScan(parentCtx context.Context, req models.ScanRequest, onProgress ProgressCallback) (*models.ScanResult, error) {
	// Guardrail #1: Mandatory legal authorization check
	if !req.AuthorizedConfirm {
		return nil, errors.New("konfirmasi izin wajib dicentang sebelum melakukan pemindaian / authorization confirmation is required before scanning")
	}

	settings := models.DefaultSettings()
	if e.store != nil {
		if s, err := e.store.GetSettings(); err == nil {
			settings = s
		}
	}

	scope, err := ParseAndValidateTarget(req.TargetURL, true)
	if err != nil {
		return nil, err
	}

	selectedIDs := ResolveProfileModules(req)
	var selectedModules []ScannerModule
	var modNames []string
	for _, id := range selectedIDs {
		if m, ok := e.modules[id]; ok {
			selectedModules = append(selectedModules, m)
			modNames = append(modNames, string(id))
		}
	}
	if len(selectedModules) == 0 {
		return nil, errors.New("tidak ada modul yang dipilih / no valid scanner modules selected")
	}

	scanID := uuid.NewString()
	ctx, cancel := context.WithCancel(parentCtx)
	e.activeMu.Lock()
	e.active[scanID] = cancel
	e.activeMu.Unlock()
	defer func() {
		e.activeMu.Lock()
		delete(e.active, scanID)
		e.activeMu.Unlock()
		cancel()
	}()

	startTime := time.Now()
	modStatuses := make([]models.ModuleStatus, len(selectedModules))
	modIndex := make(map[models.ModuleID]int, len(selectedModules))
	for i, m := range selectedModules {
		modStatuses[i] = models.ModuleStatus{
			Module: m.ID(),
			Name:   m.Name(),
			Status: "waiting",
		}
		modIndex[m.ID()] = i
	}

	result := &models.ScanResult{
		ID:                scanID,
		TargetURL:         scope.NormalizedURL,
		NormalizedHost:    scope.Hostname,
		Profile:           req.Profile,
		Status:            "running",
		AuthorizedConfirm: req.AuthorizedConfirm,
		AuthorizationNote: strings.TrimSpace(req.AuthorizationNote),
		ScopeLocked:       true,
		StartedAt:         startTime,
		ModuleStatuses:    modStatuses,
		Findings:          []models.Finding{},
		Technologies:      []models.DetectedTech{},
	}

	auditEntry := models.AuditLogEntry{
		ScanID:            scanID,
		Timestamp:         startTime,
		TargetURL:         scope.NormalizedURL,
		NormalizedHost:    scope.Hostname,
		Profile:           string(req.Profile),
		ModulesExecuted:   strings.Join(modNames, ","),
		AuthorizedConfirm: req.AuthorizedConfirm,
		AuthorizationNote: result.AuthorizationNote,
		RateLimitRPS:      settings.RateLimitRPS,
		Status:            "running",
	}
	if e.store != nil {
		_ = e.store.RecordAuditLog(auditEntry)
		_ = e.store.SaveScan(result)
	}

	client, err := NewScopedClient(scope, settings)
	if err != nil {
		result.Status = "failed"
		result.ErrorMessage = err.Error()
		result.CompletedAt = time.Now()
		result.DurationMs = time.Since(startTime).Milliseconds()
		if e.store != nil {
			_ = e.store.SaveScan(result)
		}
		return result, err
	}

	var stateMu sync.Mutex
	emitProgress := func(latest *models.Finding) {
		if onProgress == nil {
			return
		}
		stateMu.Lock()
		completedCount := 0
		statusesCopy := make([]models.ModuleStatus, len(result.ModuleStatuses))
		for i, ms := range result.ModuleStatuses {
			statusesCopy[i] = ms
			if ms.Status == "completed" || ms.Status == "failed" || ms.Status == "skipped" || ms.Status == "cancelled" {
				completedCount++
			}
		}
		pct := 0
		if len(statusesCopy) > 0 {
			pct = (completedCount * 100) / len(statusesCopy)
		}
		ev := models.ScanProgressEvent{
			ScanID:         scanID,
			TargetURL:      scope.NormalizedURL,
			Status:         result.Status,
			ProgressPct:    pct,
			ElapsedMs:      time.Since(startTime).Milliseconds(),
			RequestsSent:   client.RequestsSent(),
			ModuleStatuses: statusesCopy,
			Summary:        result.Summary,
			LatestFinding:  latest,
		}
		stateMu.Unlock()
		onProgress(ev)
	}

	emitProgress(nil)

	// Fetch baseline response once for shared inspection
	baseline, baselineErr := client.FetchBaseline(ctx)
	if baselineErr != nil && scope.Scheme == "https" {
		// Check if fallback HTTP works when user typed domain without scheme and target is HTTP-only
		if !strings.Contains(strings.TrimSpace(req.TargetURL), "://") {
			httpScope, err2 := ParseAndValidateTarget("http://"+strings.TrimSpace(req.TargetURL), true)
			if err2 == nil {
				if httpClient, err3 := NewScopedClient(httpScope, settings); err3 == nil {
					if b2, err4 := httpClient.FetchBaseline(ctx); err4 == nil {
						scope = httpScope
						client = httpClient
						baseline = b2
						baselineErr = nil
						result.TargetURL = scope.NormalizedURL
					}
				}
			}
		}
	}
	_ = baselineErr // Even if HTTP baseline fails (e.g. port 443 down), DNS/Ports/TLS modules can still report accurately

	scanCtx := &ScanContext{
		ScanID:   scanID,
		Target:   scope,
		Client:   client,
		Baseline: baseline,
		Settings: settings,
		Profile:  req.Profile,
	}

	// Separate modules into Stage 1 (all except CVE) and Stage 2 (CVE, which consumes Fingerprint output)
	var stage1 []ScannerModule
	var stage2 []ScannerModule
	hasFingerprintInStage1 := false
	hasCVE := false

	for _, m := range selectedModules {
		if m.ID() == models.ModuleCVE {
			stage2 = append(stage2, m)
			hasCVE = true
		} else {
			if m.ID() == models.ModuleFingerprint {
				hasFingerprintInStage1 = true
			}
			stage1 = append(stage1, m)
		}
	}

	// If user selected CVE in Custom profile without selecting Fingerprint, run Fingerprint silently to populate technologies
	if hasCVE && !hasFingerprintInStage1 {
		if fpMod, ok := e.modules[models.ModuleFingerprint]; ok {
			_, _ = fpMod.Run(ctx, scanCtx)
		}
	}

	runStage := func(mods []ScannerModule) {
		if len(mods) == 0 {
			return
		}
		workers := settings.MaxWorkers
		if workers <= 0 {
			workers = 5
		}
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup

		for _, mod := range mods {
			wg.Add(1)
			go func(m ScannerModule) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					stateMu.Lock()
					idx := modIndex[m.ID()]
					result.ModuleStatuses[idx].Status = "cancelled"
					stateMu.Unlock()
					emitProgress(nil)
					return
				}

				if ctx.Err() != nil {
					stateMu.Lock()
					idx := modIndex[m.ID()]
					result.ModuleStatuses[idx].Status = "cancelled"
					stateMu.Unlock()
					emitProgress(nil)
					return
				}

				modStart := time.Now()
				stateMu.Lock()
				idx := modIndex[m.ID()]
				result.ModuleStatuses[idx].Status = "running"
				result.ModuleStatuses[idx].StartedAt = modStart
				stateMu.Unlock()
				emitProgress(nil)

				findings, modErr := m.Run(ctx, scanCtx)
				modDuration := time.Since(modStart).Milliseconds()

				stateMu.Lock()
				var latestFinding *models.Finding
				for i := range findings {
					f := &findings[i]
					if f.ID == "" {
						f.ID = uuid.NewString()
					}
					f.ScanID = scanID
					f.Module = m.ID()
					if f.TargetURL == "" {
						f.TargetURL = scope.NormalizedURL
					}
					if f.Fingerprint == "" {
						f.Fingerprint = MakeFingerprint(string(m.ID()), f.RuleID, scope.Hostname, f.Title)
					}
					if f.CreatedAt.IsZero() {
						f.CreatedAt = time.Now()
					}
					if f.Confidence == "" {
						f.Confidence = models.ConfidenceHigh
					}
					result.Findings = append(result.Findings, *f)
					switch f.Severity {
					case models.SeverityHigh:
						result.Summary.High++
					case models.SeverityMedium:
						result.Summary.Medium++
					case models.SeverityLow:
						result.Summary.Low++
					default:
						result.Summary.Info++
					}
					result.Summary.Total++
					fCopy := *f
					latestFinding = &fCopy
				}

				result.ModuleStatuses[idx].DurationMs = modDuration
				result.ModuleStatuses[idx].CompletedAt = time.Now()
				result.ModuleStatuses[idx].Findings = len(findings)

				if ctx.Err() != nil {
					result.ModuleStatuses[idx].Status = "cancelled"
				} else if modErr != nil {
					result.ModuleStatuses[idx].Status = "failed"
					result.ModuleStatuses[idx].ErrorMessage = modErr.Error()
				} else {
					result.ModuleStatuses[idx].Status = "completed"
				}
				stateMu.Unlock()

				emitProgress(latestFinding)
			}(mod)
		}

		wg.Wait()
	}

	runStage(stage1)
	if ctx.Err() == nil {
		runStage(stage2)
	}

	// Sort findings by severity (High -> Medium -> Low -> Info), then title
	sort.SliceStable(result.Findings, func(i, j int) bool {
		ri := models.SeverityRank(result.Findings[i].Severity)
		rj := models.SeverityRank(result.Findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return result.Findings[i].Title < result.Findings[j].Title
	})

	result.Technologies = scanCtx.GetTechnologies()
	result.CompletedAt = time.Now()
	result.DurationMs = time.Since(startTime).Milliseconds()
	result.RequestsSent = client.RequestsSent()

	if ctx.Err() != nil {
		result.Status = "cancelled"
	} else {
		result.Status = "completed"
	}

	if e.store != nil {
		if result.Status == "completed" {
			_ = e.store.ComputeDiffAndDecorate(result)
		}
		_ = e.store.SaveScan(result)

		auditEntry.Status = result.Status
		auditEntry.DurationMs = result.DurationMs
		auditEntry.TotalFindings = result.Summary.Total
		_ = e.store.RecordAuditLog(auditEntry)
	}

	emitProgress(nil)
	return result, nil
}

// Helper to create a well-formed Finding with bilingual fields.
func NewFinding(
	module models.ModuleID,
	ruleID string,
	targetHost string,
	discriminator string,
	severity models.Severity,
	confidence models.Confidence,
	titleID, titleEN string,
	descID, descEN string,
	impactID, impactEN string,
	recID, recEN string,
	evidence string,
	targetURL string,
	cwe string,
	owasp string,
	refs []string,
) models.Finding {
	return models.Finding{
		ID:               uuid.NewString(),
		Module:           module,
		RuleID:           ruleID,
		Fingerprint:      MakeFingerprint(string(module), ruleID, targetHost, discriminator),
		Title:            titleID,
		TitleEN:          titleEN,
		Severity:         severity,
		Confidence:       confidence,
		Description:      descID,
		DescriptionEN:    descEN,
		Impact:           impactID,
		ImpactEN:         impactEN,
		Recommendation:   recID,
		RecommendationEN: recEN,
		Evidence:         evidence,
		TargetURL:        targetURL,
		CWE:              cwe,
		OWASP:            owasp,
		References:       refs,
		CreatedAt:        time.Now(),
	}
}

// FormatHeaderEvidence formats HTTP status and headers for clear proof in findings.
func FormatHeaderEvidence(headerName, value string) string {
	if value == "" {
		return fmt.Sprintf("Header '%s' tidak ditemukan pada respons HTTP.", headerName)
	}
	return fmt.Sprintf("%s: %s", headerName, value)
}
