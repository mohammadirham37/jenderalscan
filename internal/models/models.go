package models

import "time"

// Severity levels for findings
type Severity string

const (
	SeverityHigh   Severity = "High"
	SeverityMedium Severity = "Medium"
	SeverityLow    Severity = "Low"
	SeverityInfo   Severity = "Info"
)

// SeverityRank returns numeric rank for sorting (higher is more severe)
func SeverityRank(s Severity) int {
	switch s {
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Confidence levels for findings to mitigate false positives
type Confidence string

const (
	ConfidenceHigh   Confidence = "High"
	ConfidenceMedium Confidence = "Medium"
	ConfidenceLow    Confidence = "Low"
)

// ScanProfile defines preset scan depth
type ScanProfile string

const (
	ProfileQuick  ScanProfile = "Quick"
	ProfileFull   ScanProfile = "Full"
	ProfileCustom ScanProfile = "Custom"
)

// ModuleID identifies a scanner module
type ModuleID string

const (
	ModuleHeaders     ModuleID = "headers"
	ModuleTLS         ModuleID = "tls"
	ModuleCookies     ModuleID = "cookies"
	ModulePaths       ModuleID = "paths"
	ModuleFingerprint ModuleID = "fingerprint"
	ModuleCVE         ModuleID = "cve"
	ModuleCORS        ModuleID = "cors"
	ModuleDisclosure  ModuleID = "disclosure"
	ModuleDNS         ModuleID = "dns"
	ModulePorts       ModuleID = "ports"
)

// ModuleInfo describes a scanner module for the UI
type ModuleInfo struct {
	ID              ModuleID `json:"id"`
	Name            string   `json:"name"`
	NameEN          string   `json:"nameEn"`
	Description     string   `json:"description"`
	DescriptionEN   string   `json:"descriptionEn"`
	TypicalSeverity string   `json:"typicalSeverity"`
	Phase           string   `json:"phase"` // MVP, v1, v2
	DefaultQuick    bool     `json:"defaultQuick"`
	DefaultFull     bool     `json:"defaultFull"`
}

// AllModules returns metadata for all 10 PRD modules
func AllModules() []ModuleInfo {
	return []ModuleInfo{
		{
			ID:              ModuleHeaders,
			Name:            "Security Headers",
			NameEN:          "Security Headers",
			Description:     "Memeriksa HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, dan Permissions-Policy",
			DescriptionEN:   "Inspects HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy",
			TypicalSeverity: "Low–Medium",
			Phase:           "MVP",
			DefaultQuick:    true,
			DefaultFull:     true,
		},
		{
			ID:              ModuleTLS,
			Name:            "Konfigurasi TLS/SSL",
			NameEN:          "TLS/SSL Configuration",
			Description:     "Memeriksa versi protokol (TLS 1.0/1.1 usang), cipher lemah, masa berlaku & rantai sertifikat",
			DescriptionEN:   "Checks protocol versions (deprecated TLS 1.0/1.1), weak ciphers, certificate validity & chain",
			TypicalSeverity: "Medium–High",
			Phase:           "MVP",
			DefaultQuick:    true,
			DefaultFull:     true,
		},
		{
			ID:              ModuleCookies,
			Name:            "Cookie Flags",
			NameEN:          "Cookie Flags",
			Description:     "Memeriksa atribut Secure, HttpOnly, dan SameSite pada setiap cookie sesi/aplikasi",
			DescriptionEN:   "Checks Secure, HttpOnly, and SameSite flags on every response cookie",
			TypicalSeverity: "Low–Medium",
			Phase:           "MVP",
			DefaultQuick:    true,
			DefaultFull:     true,
		},
		{
			ID:              ModulePaths,
			Name:            "Path & File Sensitif",
			NameEN:          "Sensitive Paths & Files",
			Description:     "Mendeteksi paparan .git, .env, file backup, config, dokumentasi API, dan panel admin secara non-destruktif",
			DescriptionEN:   "Detects exposed .git, .env, backups, config files, API docs, and admin panels non-destructively",
			TypicalSeverity: "Medium–High",
			Phase:           "MVP",
			DefaultQuick:    true,
			DefaultFull:     true,
		},
		{
			ID:              ModuleFingerprint,
			Name:            "Tech Fingerprint",
			NameEN:          "Tech Fingerprint",
			Description:     "Mengidentifikasi web server, framework, CMS, bahasa pemrograman, WAF/CDN, dan versi dari header & HTML",
			DescriptionEN:   "Identifies web server, framework, CMS, language, WAF/CDN, and versions from headers & HTML",
			TypicalSeverity: "Info",
			Phase:           "MVP",
			DefaultQuick:    true,
			DefaultFull:     true,
		},
		{
			ID:              ModuleCVE,
			Name:            "Pencocokan CVE",
			NameEN:          "CVE Matching",
			Description:     "Memetakan nama & versi software hasil fingerprint terhadap database kerentanan CVE lokal (eksak maupun estimasi teknologi)",
			DescriptionEN:   "Maps detected software and versions from fingerprinting against the local CVE vulnerability dataset (exact & advisory)",
			TypicalSeverity: "Medium–High",
			Phase:           "v1",
			DefaultQuick:    true,
			DefaultFull:     true,
		},
		{
			ID:              ModuleCORS,
			Name:            "Konfigurasi CORS",
			NameEN:          "CORS Configuration",
			Description:     "Mendeteksi kebijakan Access-Control-Allow-Origin dan Credentials yang terlalu permisif atau memantulkan origin sembarang",
			DescriptionEN:   "Detects overly permissive Access-Control-Allow-Origin and Credentials policies or arbitrary origin reflection",
			TypicalSeverity: "Medium–High",
			Phase:           "v1",
			DefaultQuick:    false,
			DefaultFull:     true,
		},
		{
			ID:              ModuleDisclosure,
			Name:            "Information Disclosure",
			NameEN:          "Information Disclosure",
			Description:     "Mendeteksi error verbose, stack trace, komentar HTML sensitif, kebocoran IP internal, dan directory listing",
			DescriptionEN:   "Detects verbose errors, stack traces, sensitive HTML comments, internal IP leaks, and directory listing",
			TypicalSeverity: "Low–Medium",
			Phase:           "v1",
			DefaultQuick:    false,
			DefaultFull:     true,
		},
		{
			ID:              ModuleDNS,
			Name:            "DNS & Subdomain Pasif",
			NameEN:          "DNS & Passive Subdomains",
			Description:     "Memeriksa record DNS (A, AAAA, MX, NS, TXT, CAA), konfigurasi SPF/DMARC, dan enumerasi subdomain pasif",
			DescriptionEN:   "Checks DNS records (A, AAAA, MX, NS, TXT, CAA), SPF/DMARC policies, and passive subdomain enumeration",
			TypicalSeverity: "Info–Low",
			Phase:           "v2",
			DefaultQuick:    false,
			DefaultFull:     true,
		},
		{
			ID:              ModulePorts,
			Name:            "Port & Service Ringan",
			NameEN:          "Lightweight Port & Service",
			Description:     "Memeriksa port web dan manajemen umum yang terbuka pada host target secara ringan dan terbatas",
			DescriptionEN:   "Performs a lightweight, bounded check of common web and management ports open on the target host",
			TypicalSeverity: "Info–High",
			Phase:           "v2",
			DefaultQuick:    false,
			DefaultFull:     true,
		},
	}
}

// DetectedTech represents a technology component identified during fingerprinting
type DetectedTech struct {
	Name          string   `json:"name"`
	Category      string   `json:"category"` // Server, Framework, CMS, Library, CDN/WAF, Runtime
	Language      string   `json:"language,omitempty"`
	Version       string   `json:"version"`
	Confidence    string   `json:"confidence"`
	Source        string   `json:"source"`
	CPE           string   `json:"cpe,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	PotentialCVEs []string `json:"potentialCves,omitempty"`
}

// DiffStatus tracks whether a finding is new or recurring compared to the previous scan
type DiffStatus string

const (
	DiffNew       DiffStatus = "new"
	DiffRecurring DiffStatus = "recurring"
	DiffFixed     DiffStatus = "fixed"
)

// Finding represents a single security finding produced by a scanner module
type Finding struct {
	ID               string     `json:"id"`
	ScanID           string     `json:"scanId"`
	Module           ModuleID   `json:"module"`
	RuleID           string     `json:"ruleId"`
	Fingerprint      string     `json:"fingerprint"` // deterministic key for diffing across scans
	Title            string     `json:"title"`
	TitleEN          string     `json:"titleEn,omitempty"`
	Severity         Severity   `json:"severity"`
	Confidence       Confidence `json:"confidence"`
	Description      string     `json:"description"`      // "Apa ini"
	DescriptionEN    string     `json:"descriptionEn"`    // "What this is"
	Impact           string     `json:"impact"`           // "Kenapa berisiko"
	ImpactEN         string     `json:"impactEn"`         // "Why it is risky"
	Recommendation   string     `json:"recommendation"`   // "Cara perbaiki"
	RecommendationEN string     `json:"recommendationEn"` // "How to fix"
	Evidence         string     `json:"evidence"`
	TargetURL        string     `json:"targetUrl"`
	References       []string   `json:"references"` // OWASP, CWE, CVE, RFC
	CWE              string     `json:"cwe,omitempty"`
	OWASP            string     `json:"owasp,omitempty"`
	CVSS             float64    `json:"cvss,omitempty"`
	DiffStatus       DiffStatus `json:"diffStatus,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
}

// ModuleStatus tracks real-time execution status of an individual module
type ModuleStatus struct {
	Module       ModuleID  `json:"module"`
	Name         string    `json:"name"`
	Status       string    `json:"status"` // waiting, running, completed, failed, skipped, cancelled
	Findings     int       `json:"findings"`
	DurationMs   int64     `json:"durationMs"`
	ErrorMessage string    `json:"errorMessage,omitempty"`
	StartedAt    time.Time `json:"startedAt,omitempty"`
	CompletedAt  time.Time `json:"completedAt,omitempty"`
}

// SeveritySummary aggregates finding counts per severity
type SeveritySummary struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
	Total  int `json:"total"`
}

// ScanDiff summarizes changes compared to the previous scan on the same host
type ScanDiff struct {
	PreviousScanID string    `json:"previousScanId,omitempty"`
	PreviousDate   time.Time `json:"previousDate,omitempty"`
	NewCount       int       `json:"newCount"`
	RecurringCount int       `json:"recurringCount"`
	FixedCount     int       `json:"fixedCount"`
	FixedFindings  []Finding `json:"fixedFindings,omitempty"`
}

// ScanRequest is the input payload to start a scan
type ScanRequest struct {
	TargetURL         string      `json:"targetUrl"`
	Profile           ScanProfile `json:"profile"`
	Modules           []ModuleID  `json:"modules"`
	AuthorizedConfirm bool        `json:"authorizedConfirm"` // Mandatory legal guardrail
	AuthorizationNote string      `json:"authorizationNote"` // Optional scope/contract reference
}

// ScanResult is the complete record of a scan session
type ScanResult struct {
	ID                string          `json:"id"`
	TargetURL         string          `json:"targetUrl"`
	NormalizedHost    string          `json:"normalizedHost"`
	Profile           ScanProfile     `json:"profile"`
	Status            string          `json:"status"` // running, completed, cancelled, failed
	AuthorizedConfirm bool            `json:"authorizedConfirm"`
	AuthorizationNote string          `json:"authorizationNote"`
	ScopeLocked       bool            `json:"scopeLocked"`
	StartedAt         time.Time       `json:"startedAt"`
	CompletedAt       time.Time       `json:"completedAt"`
	DurationMs        int64           `json:"durationMs"`
	ModuleStatuses    []ModuleStatus  `json:"moduleStatuses"`
	Findings          []Finding       `json:"findings"`
	Technologies      []DetectedTech  `json:"technologies"`
	Summary           SeveritySummary `json:"summary"`
	Diff              *ScanDiff       `json:"diff,omitempty"`
	RequestsSent      int64           `json:"requestsSent"`
	ErrorMessage      string          `json:"errorMessage,omitempty"`
}

// ScanProgressEvent is emitted in real time during scan execution
type ScanProgressEvent struct {
	ScanID         string          `json:"scanId"`
	TargetURL      string          `json:"targetUrl"`
	Status         string          `json:"status"`
	ProgressPct    int             `json:"progressPct"`
	ElapsedMs      int64           `json:"elapsedMs"`
	RequestsSent   int64           `json:"requestsSent"`
	ModuleStatuses []ModuleStatus  `json:"moduleStatuses"`
	Summary        SeveritySummary `json:"summary"`
	LatestFinding  *Finding        `json:"latestFinding,omitempty"`
}

// AuditLogEntry records legal accountability for every scan initiated
type AuditLogEntry struct {
	ID                int64     `json:"id"`
	ScanID            string    `json:"scanId"`
	Timestamp         time.Time `json:"timestamp"`
	TargetURL         string    `json:"targetUrl"`
	NormalizedHost    string    `json:"normalizedHost"`
	Profile           string    `json:"profile"`
	ModulesExecuted   string    `json:"modulesExecuted"`
	AuthorizedConfirm bool      `json:"authorizedConfirm"`
	AuthorizationNote string    `json:"authorizationNote"`
	RateLimitRPS      int       `json:"rateLimitRps"`
	Status            string    `json:"status"`
	DurationMs        int64     `json:"durationMs"`
	TotalFindings     int       `json:"totalFindings"`
}

// AppSettings represents user-configurable settings
type AppSettings struct {
	MaxWorkers      int               `json:"maxWorkers"`      // Default: 5
	RateLimitRPS    int               `json:"rateLimitRps"`    // Default: 10 requests/second
	TimeoutSeconds  int               `json:"timeoutSeconds"`  // Default: 10s
	MaxRetries      int               `json:"maxRetries"`      // Default: 1
	UserAgent       string            `json:"userAgent"`       // Default: JenderalScan/1.0 (Non-Intrusive Security Surface Scanner)
	CustomHeaders   map[string]string `json:"customHeaders"`   // Optional custom headers
	ProxyURL        string            `json:"proxyUrl"`        // Optional HTTP/SOCKS5 proxy
	VerifyTLS       bool              `json:"verifyTls"`       // Default: false for HTTP client so broken TLS targets can still have headers scanned while TLS module inspects cert
	StrictScopeLock bool              `json:"strictScopeLock"` // Default: true (always enforce host lock)
	Language        string            `json:"language"`        // "id" or "en"
	Theme           string            `json:"theme"`           // "dark" or "light"
}

// DefaultSettings returns safe, target-polite defaults as required by the PRD
func DefaultSettings() AppSettings {
	return AppSettings{
		MaxWorkers:      5,
		RateLimitRPS:    10,
		TimeoutSeconds:  10,
		MaxRetries:      1,
		UserAgent:       "JenderalScan/1.0 (+https://jenderalscan.local; Non-Intrusive Security Audit)",
		CustomHeaders:   map[string]string{},
		ProxyURL:        "",
		VerifyTLS:       false,
		StrictScopeLock: true,
		Language:        "id",
		Theme:           "dark",
	}
}

// CVEDatasetMeta holds metadata about the local CVE vulnerability dataset
type CVEDatasetMeta struct {
	Version     string    `json:"version"`
	LastUpdated time.Time `json:"lastUpdated"`
	TotalEntries int      `json:"totalEntries"`
	Source      string    `json:"source"`
}

// CVEEntry represents a single vulnerability definition in the local dataset
type CVEEntry struct {
	CVEID          string   `json:"cveId"`
	Product        string   `json:"product"`        // normalized lowercase product name, e.g. "nginx", "apache", "php", "wordpress", "jquery", "openssh", "openssl"
	Vendor         string   `json:"vendor"`
	VersionStart   string   `json:"versionStart"`   // inclusive if set (empty means all versions up to VersionEnd)
	VersionEnd     string   `json:"versionEnd"`     // exclusive upper bound (i.e. fixed in VersionEnd)
	Severity       Severity `json:"severity"`
	CVSS           float64  `json:"cvss"`
	CWE            string   `json:"cwe"`
	SummaryID      string   `json:"summaryId"`
	SummaryEN      string   `json:"summaryEn"`
	RemediationID  string   `json:"remediationId"`
	RemediationEN  string   `json:"remediationEn"`
	References     []string `json:"references"`
	PublishedDate  string   `json:"publishedDate"`
}
