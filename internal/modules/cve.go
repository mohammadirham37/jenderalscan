package modules

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
	"jenderalscan/internal/storage"
)

//go:embed cve_data.json
var embeddedCVEJSON []byte

// CVEModule matches detected software names and versions against the local CVE dataset.
// Supports both exact version range matching and technology-level CVE estimation when version banners are hidden.
type CVEModule struct {
	mu          sync.RWMutex
	entries     []models.CVEEntry
	lastUpdated time.Time
	store       *storage.Store
}

func NewCVEModule(store *storage.Store) *CVEModule {
	m := &CVEModule{
		store:       store,
		lastUpdated: time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC),
	}
	m.reloadDataset()
	return m
}

func (m *CVEModule) reloadDataset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	var baseEntries []models.CVEEntry
	_ = json.Unmarshal(embeddedCVEJSON, &baseEntries)

	byID := make(map[string]models.CVEEntry, len(baseEntries))
	var ordered []string
	for _, e := range baseEntries {
		byID[e.CVEID] = e
		ordered = append(ordered, e.CVEID)
	}

	if m.store != nil {
		if custom, ts, err := m.store.LoadCustomCVEs(); err == nil {
			for _, ce := range custom {
				if _, exists := byID[ce.CVEID]; !exists {
					ordered = append(ordered, ce.CVEID)
				}
				byID[ce.CVEID] = ce
			}
			if ts != nil {
				m.lastUpdated = *ts
			}
		}
	}

	merged := make([]models.CVEEntry, 0, len(ordered))
	for _, id := range ordered {
		merged = append(merged, byID[id])
	}
	m.entries = merged
}

// GetDatasetMeta returns metadata about the active local CVE dataset.
func (m *CVEModule) GetDatasetMeta() models.CVEDatasetMeta {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return models.CVEDatasetMeta{
		Version:      "2026.10-NVD-Curated",
		LastUpdated:  m.lastUpdated,
		TotalEntries: len(m.entries),
		Source:       "Local Embedded NVD Snapshot + SQLite Custom Feeds",
	}
}

// ImportCustomCVEs imports additional CVE entries from JSON and persists them to SQLite.
func (m *CVEModule) ImportCustomCVEs(rawJSON string) (models.CVEDatasetMeta, error) {
	var imported []models.CVEEntry
	if err := json.Unmarshal([]byte(rawJSON), &imported); err != nil {
		return m.GetDatasetMeta(), fmt.Errorf("format JSON CVE tidak valid: %w", err)
	}
	if m.store != nil {
		if err := m.store.SaveCustomCVEs(imported); err != nil {
			return m.GetDatasetMeta(), err
		}
	}
	m.mu.Lock()
	m.lastUpdated = time.Now().UTC()
	m.mu.Unlock()
	m.reloadDataset()
	return m.GetDatasetMeta(), nil
}

// RefreshDataset refreshes the dataset timestamp and reloads SQLite overrides.
func (m *CVEModule) RefreshDataset() (models.CVEDatasetMeta, error) {
	if m.store != nil {
		_ = m.store.SaveCustomCVEs(nil)
	}
	m.mu.Lock()
	m.lastUpdated = time.Now().UTC()
	m.mu.Unlock()
	m.reloadDataset()
	return m.GetDatasetMeta(), nil
}

func (m *CVEModule) ID() models.ModuleID {
	return models.ModuleCVE
}

func (m *CVEModule) Name() string {
	return "Pencocokan CVE"
}

func (m *CVEModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
	techs := scanCtx.GetTechnologies()
	if len(techs) == 0 {
		return nil, nil
	}

	m.mu.RLock()
	entries := make([]models.CVEEntry, len(m.entries))
	copy(entries, m.entries)
	m.mu.RUnlock()

	host := scanCtx.Target.Hostname
	targetURL := scanCtx.Target.NormalizedURL
	if scanCtx.Baseline != nil && scanCtx.Baseline.FinalURL != "" {
		targetURL = scanCtx.Baseline.FinalURL
	}

	var findings []models.Finding

	for _, tech := range techs {
		normProd := strings.ToLower(strings.TrimSpace(tech.Name))

		// Tier 1: Exact Version Detected -> Match exact vulnerable range
		if tech.Version != "" {
			for _, cve := range entries {
				if !strings.EqualFold(cve.Product, normProd) {
					continue
				}
				if isVersionInRange(tech.Version, cve.VersionStart, cve.VersionEnd) {
					scanCtx.AttachTechCVE(tech.Name, fmt.Sprintf("%s (CVSS %.1f)", cve.CVEID, cve.CVSS))

					f := engine.NewFinding(
						models.ModuleCVE,
						"CVE-"+cve.CVEID,
						host,
						cve.CVEID+"-"+tech.Name+"-"+tech.Version,
						cve.Severity,
						models.ConfidenceHigh,
						fmt.Sprintf("%s pada %s %s (CVSS %.1f)", cve.CVEID, tech.Name, tech.Version, cve.CVSS),
						fmt.Sprintf("%s in %s %s (CVSS %.1f)", cve.CVEID, tech.Name, tech.Version, cve.CVSS),
						cve.SummaryID,
						cve.SummaryEN,
						fmt.Sprintf("Versi %s `%s` yang terdeteksi berada dalam rentang versi rentan (%s <= v < %s) untuk %s.", tech.Name, tech.Version, cve.VersionStart, cve.VersionEnd, cve.CVEID),
						fmt.Sprintf("The detected %s version `%s` falls within the vulnerable range (%s <= v < %s) for %s.", tech.Name, tech.Version, cve.VersionStart, cve.VersionEnd, cve.CVEID),
						cve.RemediationID,
						cve.RemediationEN,
						fmt.Sprintf("Komponen Terdeteksi: %s %s\nSumber Deteksi: %s\nRentang Rentan: >= %s, < %s\nCVSS v3: %.1f", tech.Name, tech.Version, tech.Source, cve.VersionStart, cve.VersionEnd, cve.CVSS),
						targetURL,
						cve.CWE,
						"OWASP A06:2021 - Vulnerable and Outdated Components",
						cve.References,
					)
					f.CVSS = cve.CVSS
					findings = append(findings, f)
				}
			}
			continue
		}

		// Tier 2: Technology Detected WITHOUT visible version (e.g. Laravel, PHP, Go, Rust, Next.js, Express, Django)
		// Provide estimated / potential CVE candidates for this technology with Low (Advisory) confidence
		var candidateCVEs []models.CVEEntry
		for _, cve := range entries {
			if strings.EqualFold(cve.Product, normProd) {
				candidateCVEs = append(candidateCVEs, cve)
				scanCtx.AttachTechCVE(tech.Name, fmt.Sprintf("? %s (<%s)", cve.CVEID, cve.VersionEnd))
			}
		}

		if len(candidateCVEs) > 0 {
			var cveIDs []string
			var detailLines []string
			var refs []string
			maxCVSS := 0.0
			primaryCWE := candidateCVEs[0].CWE

			for _, cve := range candidateCVEs {
				cveIDs = append(cveIDs, cve.CVEID)
				detailLines = append(detailLines, fmt.Sprintf(
					"• %s (CVSS %.1f, rentan jika versi < %s): %s\n  Solusi: %s",
					cve.CVEID, cve.CVSS, cve.VersionEnd, cve.SummaryID, cve.RemediationID,
				))
				refs = append(refs, cve.References...)
				if cve.CVSS > maxCVSS {
					maxCVSS = cve.CVSS
				}
			}

			f := engine.NewFinding(
				models.ModuleCVE,
				"CVE-ESTIMATE-"+strings.ToUpper(strings.ReplaceAll(normProd, " ", "-")),
				host,
				"cve-estimate-"+normProd,
				models.SeverityLow,
				models.ConfidenceLow,
				fmt.Sprintf("Estimasi Potensi CVE untuk %s (%s)", tech.Name, strings.Join(cveIDs, ", ")),
				fmt.Sprintf("Potential CVE Advisory for %s (%s)", tech.Name, strings.Join(cveIDs, ", ")),
				fmt.Sprintf("Teknologi `%s` terdeteksi pada target (%s), namun nomor versi spesifik disembunyikan oleh server. Berdasarkan profil teknologi ini, terdapat %d CVE signifikan yang perlu diverifikasi terhadap versi yang terpasang.", tech.Name, tech.Source, len(candidateCVEs)),
				fmt.Sprintf("Technology `%s` was detected on the target (%s), though its exact version number is hidden. Based on this technology profile, %d notable CVEs should be verified against your installed version.", tech.Name, tech.Source, len(candidateCVEs)),
				fmt.Sprintf("Apabila instalasi `%s` belum diperbarui ke versi aman, aplikasi berisiko terdampak kerentanan %s (skor CVSS hingga %.1f).", tech.Name, strings.Join(cveIDs, ", "), maxCVSS),
				fmt.Sprintf("If your `%s` installation is older than the patched release thresholds, it may be exposed to %s (CVSS up to %.1f).", tech.Name, strings.Join(cveIDs, ", "), maxCVSS),
				fmt.Sprintf("Periksa versi `%s` pada manajer paket internal (`composer.lock`, `go.mod`, `Cargo.lock`, `package-lock.json`, atau `requirements.txt`) dan pastikan berada di atas batas versi aman pada daftar bukti di bawah.", tech.Name),
				fmt.Sprintf("Verify the exact version of `%s` in your internal lockfile (`composer.lock`, `go.mod`, `Cargo.lock`, `package-lock.json`, or `requirements.txt`) and ensure it meets the patched versions listed below.", tech.Name),
				fmt.Sprintf("Teknologi Terdeteksi: %s (Versi disembunyikan di respons publik)\nSumber Deteksi: %s\nDaftar CVE yang Perlu Diverifikasi:\n%s", tech.Name, tech.Source, strings.Join(detailLines, "\n\n")),
				targetURL,
				primaryCWE,
				"OWASP A06:2021 - Vulnerable and Outdated Components",
				refs,
			)
			f.CVSS = maxCVSS
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// isVersionInRange checks if version v satisfies versionStart <= v < versionEnd.
func isVersionInRange(v, start, end string) bool {
	if end == "" {
		return false
	}
	if start != "" && compareVersions(v, start) < 0 {
		return false
	}
	return compareVersions(v, end) < 0
}

// compareVersions compares two semantic-like version strings (including OpenSSL suffix letters like 1.1.1k vs 1.1.1n).
func compareVersions(a, b string) int {
	pa, sa := parseVersionParts(a)
	pb, sb := parseVersionParts(b)

	maxLen := len(pa)
	if len(pb) > maxLen {
		maxLen = len(pb)
	}
	for i := 0; i < maxLen; i++ {
		va := 0
		if i < len(pa) {
			va = pa[i]
		}
		vb := 0
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	if sa < sb {
		return -1
	}
	if sa > sb {
		return 1
		}
	return 0
}

func parseVersionParts(v string) ([]int, string) {
	v = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(v), "v"))
	if idx := strings.IndexAny(v, "-+_ "); idx >= 0 {
		v = v[:idx]
	}
	rawParts := strings.Split(v, ".")
	var nums []int
	var suffix string
	for _, p := range rawParts {
		digits := ""
		rest := ""
		for i, ch := range p {
			if ch >= '0' && ch <= '9' {
				digits += string(ch)
			} else {
				rest = p[i:]
				break
			}
		}
		n, _ := strconv.Atoi(digits)
		nums = append(nums, n)
		if rest != "" {
			suffix = rest
		}
	}
	return nums, suffix
}
