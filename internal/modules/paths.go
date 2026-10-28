package modules

import (
	"context"
	"fmt"
	"math"
	"strings"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
)

// PathsModule checks for exposed sensitive files, directories, configs, backups, and panels non-destructively.
type PathsModule struct{}

func NewPathsModule() *PathsModule {
	return &PathsModule{}
}

func (m *PathsModule) ID() models.ModuleID {
	return models.ModulePaths
}

func (m *PathsModule) Name() string {
	return "Path & File Sensitif"
}

type pathProbe struct {
	Path             string
	RuleID           string
	Severity         models.Severity
	TitleID          string
	TitleEN          string
	DescID           string
	DescEN           string
	ImpactID         string
	ImpactEN         string
	RecID            string
	RecEN            string
	CWE              string
	MustContainAny   []string
	ForbidHTML       bool
	QuickIncluded    bool
}

var curatedProbes = []pathProbe{
	{
		Path:           "/.git/HEAD",
		RuleID:         "PATH-GIT-HEAD",
		Severity:       models.SeverityHigh,
		TitleID:        "Repositori Git (.git/HEAD) Terekspos ke Publik",
		TitleEN:        "Exposed Git Repository (.git/HEAD)",
		DescID:         "File `/.git/HEAD` dapat diakses secara publik dan berisi referensi branch Git.",
		DescEN:         "The `/.git/HEAD` file is publicly accessible and contains a valid Git branch reference.",
		ImpactID:       "Penyerang dapat mengunduh seluruh riwayat source code, konfigurasi aplikasi, serta kredensial atau API key yang pernah di-commit.",
		ImpactEN:       "Attackers can reconstruct the entire application source code repository, commit history, and hardcoded secrets.",
		RecID:          "Blokir akses ke direktori `.git` pada konfigurasi web server (mis. `location ~ /\\.git { deny all; }` di Nginx) dan jangan menyertakan `.git` pada direktori deployment produksi.",
		RecEN:          "Deny access to `.git` directories in your web server configuration (e.g., `location ~ /\\.git { deny all; }` in Nginx) and exclude `.git` from production deployments.",
		CWE:            "CWE-538",
		MustContainAny: []string{"ref: refs/", "refs/heads/"},
		ForbidHTML:     true,
		QuickIncluded:  true,
	},
	{
		Path:           "/.git/config",
		RuleID:         "PATH-GIT-CONFIG",
		Severity:       models.SeverityHigh,
		TitleID:        "File Konfigurasi Git (.git/config) Terekspos ke Publik",
		TitleEN:        "Exposed Git Configuration (.git/config)",
		DescID:         "File `/.git/config` dapat diakses secara publik.",
		DescEN:         "The `/.git/config` file is publicly accessible.",
		ImpactID:       "Membocorkan URL remote repositori internal, struktur branch, dan terkadang token akses di URL remote.",
		ImpactEN:       "Exposes internal repository remote URLs, branch configuration, and potentially embedded access tokens.",
		RecID:          "Blokir akses ke seluruh file tersembunyi (dotfile) yang diawali titik (`.`) di web server.",
		RecEN:          "Block access to all dotfiles (files starting with `.`) at the web server level.",
		CWE:            "CWE-538",
		MustContainAny: []string{"[core]", "[remote", "repositoryformatversion"},
		ForbidHTML:     true,
		QuickIncluded:  true,
	},
	{
		Path:           "/.env",
		RuleID:         "PATH-ENV-FILE",
		Severity:       models.SeverityHigh,
		TitleID:        "File Environment (.env) Terekspos ke Publik",
		TitleEN:        "Exposed Environment Configuration File (.env)",
		DescID:         "File konfigurasi environment `/.env` dapat diunduh secara langsung.",
		DescEN:         "The `/.env` environment configuration file is directly downloadable.",
		ImpactID:       "File `.env` umumnya menyimpan password database, APP_KEY, secret JWT, serta kredensial layanan pihak ketiga (AWS, SMTP, Payment Gateway).",
		ImpactEN:       "The `.env` file typically stores database passwords, application encryption keys, JWT secrets, and third-party API credentials.",
		RecID:          "Pindahkan `.env` ke luar document root publik (`public/`), blokir akses dotfile di web server, dan segera rotasi semua kredensial yang pernah ada di dalam file tersebut.",
		RecEN:          "Move `.env` outside the web document root, deny dotfile access in the web server, and immediately rotate all secrets contained within the file.",
		CWE:            "CWE-215",
		MustContainAny: []string{"APP_ENV=", "APP_KEY=", "DB_HOST=", "DB_PASSWORD=", "DATABASE_URL=", "SECRET_KEY=", "API_KEY=", "NODE_ENV=", "PORT="},
		ForbidHTML:     true,
		QuickIncluded:  true,
	},
	{
		Path:           "/phpinfo.php",
		RuleID:         "PATH-PHPINFO",
		Severity:       models.SeverityMedium,
		TitleID:        "Halaman diagnostik phpinfo.php Terekspos",
		TitleEN:        "Exposed phpinfo.php Diagnostic Page",
		DescID:         "File `/phpinfo.php` aktif dan menampilkan konfigurasi internal runtime PHP.",
		DescEN:         "The `/phpinfo.php` script is accessible and outputs internal PHP runtime configuration.",
		ImpactID:       "Membocorkan versi detail PHP, ekstensi, path sistem file server, variabel environment (`$_ENV`/`$_SERVER`), dan batas konfigurasi keamanan.",
		ImpactEN:       "Discloses exact PHP versions, loaded extensions, filesystem paths, environment variables, and security directives.",
		RecID:          "Hapus file `phpinfo.php` dari server produksi.",
		RecEN:          "Remove `phpinfo.php` from production servers immediately.",
		CWE:            "CWE-200",
		MustContainAny: []string{"phpinfo()", "PHP Version", "Zend Engine"},
		ForbidHTML:     false,
		QuickIncluded:  true,
	},
	{
		Path:           "/actuator/env",
		RuleID:         "PATH-ACTUATOR-ENV",
		Severity:       models.SeverityHigh,
		TitleID:        "Endpoint Spring Boot Actuator (/actuator/env) Terekspos",
		TitleEN:        "Exposed Spring Boot Actuator Endpoint (/actuator/env)",
		DescID:         "Endpoint manajemen `/actuator/env` dapat diakses tanpa autentikasi.",
		DescEN:         "The `/actuator/env` Spring Boot management endpoint is accessible without authentication.",
		ImpactID:       "Membocorkan properti sistem, variabel environment, dan konfigurasi layanan internal.",
		ImpactEN:       "Exposes internal system properties, environment variables, and service configuration.",
		RecID:          "Batasi eksposur endpoint Actuator di `application.properties` (`management.endpoints.web.exposure.include=health`) dan lindungi dengan autentikasi.",
		RecEN:          "Restrict Actuator endpoint exposure (`management.endpoints.web.exposure.include=health`) and enforce authentication.",
		CWE:            "CWE-200",
		MustContainAny: []string{"propertySources", "activeProfiles", "systemProperties"},
		ForbidHTML:     true,
		QuickIncluded:  true,
	},
	{
		Path:           "/actuator/health",
		RuleID:         "PATH-ACTUATOR-HEALTH",
		Severity:       models.SeverityLow,
		TitleID:        "Endpoint Spring Boot Actuator (/actuator/health) Publik",
		TitleEN:        "Public Spring Boot Actuator Health Endpoint (/actuator/health)",
		DescID:         "Endpoint `/actuator/health` dapat diakses secara publik.",
		DescEN:         "The `/actuator/health` endpoint is publicly accessible.",
		ImpactID:       "Jika `show-details=always` aktif, dapat membocorkan status dan jenis database, cache, serta disk internal.",
		ImpactEN:       "If `show-details` is enabled, it may disclose internal database, cache, and disk component details.",
		RecID:          "Pastikan `management.endpoint.health.show-details=never` untuk akses publik.",
		RecEN:          "Ensure `management.endpoint.health.show-details=never` for unauthenticated callers.",
		CWE:            "CWE-200",
		MustContainAny: []string{`"status":"UP"`, `"status":"DOWN"`, `"components":{`},
		ForbidHTML:     true,
		QuickIncluded:  false,
	},
	{
		Path:           "/server-status",
		RuleID:         "PATH-SERVER-STATUS",
		Severity:       models.SeverityMedium,
		TitleID:        "Halaman Apache mod_status (/server-status) Terekspos",
		TitleEN:        "Exposed Apache mod_status (/server-status) Page",
		DescID:         "Halaman status internal Apache `/server-status` dapat diakses dari luar.",
		DescEN:         "The Apache `/server-status` internal status page is publicly accessible.",
		ImpactID:       "Membocorkan daftar URL aktif yang sedang diakses pengguna lain, alamat IP klien, serta beban worker internal.",
		ImpactEN:       "Exposes active client IP addresses, live request URLs being processed, and internal worker telemetry.",
		RecID:          "Batasi akses `/server-status` hanya untuk IP localhost (`Require local` di konfigurasi Apache).",
		RecEN:          "Restrict `/server-status` access to localhost (`Require local` in Apache configuration).",
		CWE:            "CWE-200",
		MustContainAny: []string{"Apache Server Status", "Server Version:", "Current Time:"},
		ForbidHTML:     false,
		QuickIncluded:  true,
	},
	{
		Path:           "/wp-config.php.bak",
		RuleID:         "PATH-WP-CONFIG-BAK",
		Severity:       models.SeverityHigh,
		TitleID:        "File Backup Konfigurasi WordPress (wp-config.php.bak) Terekspos",
		TitleEN:        "Exposed WordPress Configuration Backup (wp-config.php.bak)",
		DescID:         "File cadangan `/wp-config.php.bak` tidak dieksekusi oleh PHP dan dapat diunduh sebagai teks mentah.",
		DescEN:         "The backup file `/wp-config.php.bak` is not executed by the PHP interpreter and is downloadable as plaintext.",
		ImpactID:       "Membocorkan kredensial database MySQL (`DB_PASSWORD`) dan kunci autentikasi WordPress secara langsung.",
		ImpactEN:       "Directly exposes MySQL database credentials (`DB_PASSWORD`) and WordPress authentication salts.",
		RecID:          "Hapus semua file `.bak`, `.old`, `.swp` dari direktori publik dan rotasi password database.",
		RecEN:          "Delete all `.bak`, `.old`, and `.swp` backup files from the web root and rotate database credentials.",
		CWE:            "CWE-530",
		MustContainAny: []string{"DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"},
		ForbidHTML:     true,
		QuickIncluded:  true,
	},
	{
		Path:           "/backup.sql",
		RuleID:         "PATH-BACKUP-SQL",
		Severity:       models.SeverityHigh,
		TitleID:        "File Dump Database (/backup.sql) Terekspos ke Publik",
		TitleEN:        "Exposed Database Dump File (/backup.sql)",
		DescID:         "File dump SQL `/backup.sql` dapat diunduh secara langsung oleh publik.",
		DescEN:         "A database SQL dump file (`/backup.sql`) is publicly accessible.",
		ImpactID:       "Membocorkan skema dan seluruh data tabel database termasuk data pengguna dan hash password.",
		ImpactEN:       "Exposes database schemas and sensitive application records including user data and password hashes.",
		RecID:          "Hapus file `.sql` dari web root dan simpan backup di penyimpanan objek privat yang terenkripsi.",
		RecEN:          "Remove `.sql` files from the web root and store database backups in private encrypted storage.",
		CWE:            "CWE-530",
		MustContainAny: []string{"CREATE TABLE", "INSERT INTO", "mysqldump", "PostgreSQL database dump"},
		ForbidHTML:     true,
		QuickIncluded:  true,
	},
	{
		Path:           "/.DS_Store",
		RuleID:         "PATH-DS-STORE",
		Severity:       models.SeverityLow,
		TitleID:        "File Metadata macOS (.DS_Store) Terekspos",
		TitleEN:        "Exposed macOS Directory Metadata (.DS_Store)",
		DescID:         "File `/.DS_Store` ditemukan pada direktori web.",
		DescEN:         "A macOS `/.DS_Store` metadata file is accessible in the web root.",
		ImpactID:       "File biner `.DS_Store` berisi daftar nama file dan subdirektori di dalam folder tersebut, membantu penyerang memetakan file tersembunyi.",
		ImpactEN:       "`.DS_Store` binary files contain a list of sibling filenames and subdirectories, aiding attackers in discovering unlisted files.",
		RecID:          "Hapus file `.DS_Store` dari server dan tambahkan aturan blokir dotfile pada web server.",
		RecEN:          "Delete `.DS_Store` files from the server and block dotfile access in the web server configuration.",
		CWE:            "CWE-538",
		MustContainAny: []string{"Bud1"},
		ForbidHTML:     true,
		QuickIncluded:  false,
	},
	{
		Path:           "/swagger.json",
		RuleID:         "PATH-SWAGGER-JSON",
		Severity:       models.SeverityLow,
		TitleID:        "Spesifikasi API OpenAPI/Swagger (/swagger.json) Publik",
		TitleEN:        "Public OpenAPI/Swagger Specification (/swagger.json)",
		DescID:         "Dokumentasi skema API `/swagger.json` dapat diakses tanpa autentikasi.",
		DescEN:         "The `/swagger.json` API specification is accessible without authentication.",
		ImpactID:       "Memudahkan pemetaan seluruh endpoint API, parameter input, serta endpoint internal apabila tidak sengaja dipublikasikan di produksi.",
		ImpactEN:       "Reveals all API endpoints, parameters, and data models, expanding the observable attack surface if not intended to be public.",
		RecID:          "Pastikan hanya dokumentasi API publik yang diekspos, atau batasi akses Swagger pada lingkungan produksi menggunakan autentikasi.",
		RecEN:          "Verify whether the API specification is intended to be public; otherwise restrict access in production.",
		CWE:            "CWE-200",
		MustContainAny: []string{`"swagger":`, `"openapi":`, `"paths":`},
		ForbidHTML:     true,
		QuickIncluded:  true,
	},
	{
		Path:           "/openapi.json",
		RuleID:         "PATH-OPENAPI-JSON",
		Severity:       models.SeverityLow,
		TitleID:        "Spesifikasi API OpenAPI (/openapi.json) Publik",
		TitleEN:        "Public OpenAPI Specification (/openapi.json)",
		DescID:         "Dokumentasi skema API `/openapi.json` dapat diakses tanpa autentikasi.",
		DescEN:         "The `/openapi.json` API specification is accessible without authentication.",
		ImpactID:       "Memudahkan pemetaan seluruh endpoint API dan struktur data di lingkungan produksi.",
		ImpactEN:       "Reveals all API endpoints and request schemas in production.",
		RecID:          "Nonaktifkan dokumentasi OpenAPI otomatis di produksi apabila API bersifat internal.",
		RecEN:          "Disable automatic OpenAPI spec generation in production if the API is internal.",
		CWE:            "CWE-200",
		MustContainAny: []string{`"openapi":`, `"swagger":`, `"paths":`},
		ForbidHTML:     true,
		QuickIncluded:  false,
	},
}

func (m *PathsModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
	host := scanCtx.Target.Hostname
	var findings []models.Finding

	// Step 1: Soft-404 baseline calibration to prevent false positives on Single Page Applications
	notFoundURL := scanCtx.Target.ResolvePath("/jenderalscan-404-calibration-8a9b2c3d")
	nfResp, nfBody, _ := scanCtx.Client.Get(ctx, notFoundURL, false)
	soft404Len := -1
	if nfResp != nil && nfResp.StatusCode == 200 {
		soft404Len = len(nfBody)
	}

	// Step 2: Check curated sensitive paths
	for _, probe := range curatedProbes {
		if ctx.Err() != nil {
			break
		}
		if scanCtx.Profile == models.ProfileQuick && !probe.QuickIncluded {
			continue
		}

		probeURL := scanCtx.Target.ResolvePath(probe.Path)
		resp, body, err := scanCtx.Client.Get(ctx, probeURL, false)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}

		// Anti-False-Positive Checks
		if soft404Len >= 0 && math.Abs(float64(len(body)-soft404Len)) < 32 {
			// Matches soft-404 catch-all length
			continue
		}

		bodyStr := string(body)
		lowerBody := strings.ToLower(bodyStr)
		ct := strings.ToLower(resp.Header.Get("Content-Type"))

		if probe.ForbidHTML {
			if strings.Contains(ct, "text/html") || strings.Contains(lowerBody, "<!doctype html") || strings.Contains(lowerBody, "<html") {
				continue
			}
		}

		matchedSig := ""
		for _, sig := range probe.MustContainAny {
			if strings.Contains(bodyStr, sig) {
				matchedSig = sig
				break
			}
		}
		if len(probe.MustContainAny) > 0 && matchedSig == "" {
			continue
		}

		snippet := strings.TrimSpace(bodyStr)
		if len(snippet) > 240 {
			snippet = snippet[:240] + "..."
		}

		findings = append(findings, engine.NewFinding(
			models.ModulePaths,
			probe.RuleID,
			host,
			probe.Path,
			probe.Severity,
			models.ConfidenceHigh,
			probe.TitleID,
			probe.TitleEN,
			probe.DescID,
			probe.DescEN,
			probe.ImpactID,
			probe.ImpactEN,
			probe.RecID,
			probe.RecEN,
			fmt.Sprintf("GET %s → HTTP %d\nMatched Signature: %s\nSnippet:\n%s", probeURL, resp.StatusCode, matchedSig, snippet),
			probeURL,
			probe.CWE,
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{
				"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
				"https://cwe.mitre.org/data/definitions/538.html",
			},
		))
	}

	// Step 3: Inspect /robots.txt for sensitive disallowed entries
	if ctx.Err() == nil {
		robotsURL := scanCtx.Target.ResolvePath("/robots.txt")
		resp, body, err := scanCtx.Client.Get(ctx, robotsURL, false)
		if err == nil && resp != nil && resp.StatusCode == 200 {
			bodyStr := string(body)
			lower := strings.ToLower(bodyStr)
			if strings.Contains(lower, "user-agent:") && (strings.Contains(lower, "disallow:") || strings.Contains(lower, "allow:")) {
				var sensitiveDisallowed []string
				sensitiveWords := []string{"admin", "backup", "config", "private", "secret", "internal", "db", "staging", "debug", "api", "git", "env"}
				for _, line := range strings.Split(bodyStr, "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(strings.ToLower(line), "disallow:") {
						val := strings.TrimSpace(line[len("disallow:"):])
						for _, sw := range sensitiveWords {
							if strings.Contains(strings.ToLower(val), sw) {
								sensitiveDisallowed = append(sensitiveDisallowed, val)
								break
							}
						}
					}
				}
				if len(sensitiveDisallowed) > 0 {
					findings = append(findings, engine.NewFinding(
						models.ModulePaths,
						"PATH-ROBOTS-SENSITIVE",
						host,
						"robots-sensitive",
						models.SeverityLow,
						models.ConfidenceHigh,
						"File robots.txt Mengungkapkan Path Internal/Sensitif",
						"robots.txt Discloses Sensitive or Internal Paths",
						fmt.Sprintf("File `/robots.txt` mencantumkan direktif `Disallow` yang merujuk ke path sensitif (%s).", strings.Join(sensitiveDisallowed, ", ")),
						fmt.Sprintf("The `/robots.txt` file contains `Disallow` entries pointing to sensitive paths (%s).", strings.Join(sensitiveDisallowed, ", ")),
						"`robots.txt` bersifat publik dan sering digunakan penyerang untuk menemukan lokasi panel admin atau direktori tersembunyi.",
						"`robots.txt` is publicly readable and frequently used during reconnaissance to locate hidden administrative endpoints or directories.",
						"Jangan mengandalkan `robots.txt` untuk menyembunyikan path sensitif; terapkan autentikasi dan kontrol akses yang kuat pada setiap endpoint tersebut.",
						"Do not rely on `robots.txt` to hide sensitive routes; enforce proper authentication and access control on those endpoints.",
						fmt.Sprintf("URL: %s\nSensitive Disallow Entries: %s", robotsURL, strings.Join(sensitiveDisallowed, ", ")),
						robotsURL,
						"CWE-200",
						"OWASP A05:2021 - Security Misconfiguration",
						[]string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"},
					))
				}
			}
		}
	}

	return findings, nil
}
