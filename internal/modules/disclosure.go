package modules

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"

	"golang.org/x/net/html"
)

// DisclosureModule checks for verbose banners, stack traces, directory listings, sensitive HTML comments, and internal IP leaks.
type DisclosureModule struct{}

func NewDisclosureModule() *DisclosureModule {
	return &DisclosureModule{}
}

func (m *DisclosureModule) ID() models.ModuleID {
	return models.ModuleDisclosure
}

func (m *DisclosureModule) Name() string {
	return "Information Disclosure"
}

var (
	versionDigitRegex = regexp.MustCompile(`[0-9]+\.[0-9]+`)
	privateIPRegex    = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b`)
	errorPatterns     = []struct {
		pattern string
		label   string
	}{
		{"Fatal error:", "PHP Fatal Error"},
		{"Stack trace:", "Application Stack Trace"},
		{"Traceback (most recent call last):", "Python Traceback"},
		{"SQLSTATE[", "PDO/SQL Database Error"},
		{"You have an error in your SQL syntax", "MySQL Syntax Error"},
		{"Whoops, looks like something went wrong", "Laravel Debug Page"},
		{"DisallowedHost at /", "Django Debug Page"},
		{"Server Error in '/' Application", "ASP.NET Detailed Error"},
		{"Exception in thread \"", "Java Exception Stack Trace"},
	}
	commentSensitiveWords = []string{
		"todo", "fixme", "hack", "bug", "password", "passwd", "secret",
		"api_key", "apikey", "token", "admin", "internal", "staging", "debug", "credentials",
	}
)

func (m *DisclosureModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
	base := scanCtx.Baseline
	if base == nil {
		var err error
		base, err = scanCtx.Client.FetchBaseline(ctx)
		if err != nil {
			return nil, fmt.Errorf("gagal mengambil respons HTTP: %w", err)
		}
	}
	if base == nil {
		return nil, nil
	}

	host := scanCtx.Target.Hostname
	targetURL := base.FinalURL
	if targetURL == "" {
		targetURL = scanCtx.Target.NormalizedURL
	}

	var findings []models.Finding

	// 1. Verbose Version Banner in Headers
	var verboseHeaders []string
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime"} {
		val := strings.TrimSpace(base.Headers.Get(h))
		if val != "" && (versionDigitRegex.MatchString(val) || h == "X-Powered-By") {
			verboseHeaders = append(verboseHeaders, fmt.Sprintf("%s: %s", h, val))
		}
	}
	if len(verboseHeaders) > 0 {
		findings = append(findings, engine.NewFinding(
			models.ModuleDisclosure,
			"DISC-VERBOSE-BANNER",
			host,
			"verbose-banner",
			models.SeverityLow,
			models.ConfidenceHigh,
			"Banner Header HTTP Mengungkapkan Detail Versi Server/Runtime",
			"HTTP Response Headers Disclose Verbose Server/Runtime Versions",
			"Server mengirimkan header HTTP yang mencantumkan nama dan versi spesifik perangkat lunak backend.",
			"The server returns HTTP headers containing specific backend software names and version numbers.",
			"Memudahkan penyerang melakukan reconnaissance pasif dan memilih exploit yang sesuai dengan versi software target.",
			"Facilitates passive reconnaissance by allowing attackers to pinpoint exact software versions without active probing.",
			"Sembunyikan header `X-Powered-By` dan matikan nomor versi pada header `Server` (mis. `server_tokens off;` pada Nginx, `ServerTokens Prod` pada Apache, `app.disable('x-powered-by')` pada Express).",
			"Remove `X-Powered-By` headers and disable version numbers in `Server` banners (`server_tokens off;` in Nginx, `ServerTokens Prod` in Apache, `app.disable('x-powered-by')` in Express).",
			strings.Join(verboseHeaders, "\n"),
			targetURL,
			"CWE-200",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
				"https://cwe.mitre.org/data/definitions/200.html",
			},
		))
	}

	// 2. Private IP Leak in Headers
	var leakedIPs []string
	for k, vals := range base.Headers {
		joined := strings.Join(vals, ", ")
		if matches := privateIPRegex.FindAllString(joined, -1); len(matches) > 0 {
			leakedIPs = append(leakedIPs, fmt.Sprintf("%s: %s (IP: %s)", k, joined, strings.Join(matches, ", ")))
		}
	}
	if len(leakedIPs) > 0 {
		findings = append(findings, engine.NewFinding(
			models.ModuleDisclosure,
			"DISC-PRIVATE-IP-HEADER",
			host,
			"private-ip-header",
			models.SeverityLow,
			models.ConfidenceHigh,
			"Kebocoran Alamat IP Internal (RFC 1918) pada Header HTTP",
			"Internal Private IP Address (RFC 1918) Disclosed in HTTP Headers",
			"Header respons HTTP mengandung alamat IP jaringan privat internal (10.x.x.x, 172.16-31.x.x, atau 192.168.x.x).",
			"HTTP response headers contain internal RFC 1918 private network IP addresses.",
			"Mengungkapkan topologi jaringan internal di balik reverse proxy atau load balancer, yang berguna bagi penyerang saat merancang serangan SSRF.",
			"Reveals internal network topology behind reverse proxies or load balancers, aiding attackers in crafting SSRF payloads.",
			"Konfigurasikan reverse proxy/load balancer untuk membersihkan header upstream internal sebelum dikirim ke klien.",
			"Configure your reverse proxy or load balancer to strip internal upstream IP headers before returning responses to clients.",
			strings.Join(leakedIPs, "\n"),
			targetURL,
			"CWE-200",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://cwe.mitre.org/data/definitions/200.html"},
		))
	}

	bodyStr := string(base.Body)
	lowerBody := strings.ToLower(bodyStr)

	// 3. Directory Listing Enabled
	if strings.Contains(lowerBody, "<title>index of /") ||
		strings.Contains(lowerBody, "<h1>index of /") ||
		strings.Contains(lowerBody, "directory listing for /") {
		findings = append(findings, engine.NewFinding(
			models.ModuleDisclosure,
			"DISC-DIR-LISTING",
			host,
			"dir-listing",
			models.SeverityMedium,
			models.ConfidenceHigh,
			"Directory Listing Aktif pada Web Server",
			"Directory Listing Enabled on Web Server",
			"Web server menampilkan daftar isi direktori secara langsung ketika tidak ada file indeks.",
			"The web server automatically lists directory contents when no index file is present.",
			"Pengunjung dapat menelusuri dan mengunduh seluruh file di dalam direktori termasuk skrip cadangan, log, atau dokumen internal.",
			"Visitors can browse and download all files within the directory, including backup scripts, logs, or internal documents.",
			"Nonaktifkan autoindex pada web server (`autoindex off;` di Nginx atau `Options -Indexes` di Apache).",
			"Disable directory indexing in your web server configuration (`autoindex off;` in Nginx or `Options -Indexes` in Apache).",
			fmt.Sprintf("URL: %s\nIndikator HTML: <title>Index of / ...", targetURL),
			targetURL,
			"CWE-548",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://cwe.mitre.org/data/definitions/548.html"},
		))
	}

	// 4. Verbose Error / Stack Trace in Body
	var matchedErrors []string
	for _, ep := range errorPatterns {
		if strings.Contains(bodyStr, ep.pattern) {
			matchedErrors = append(matchedErrors, fmt.Sprintf("%s (%q)", ep.label, ep.pattern))
		}
	}
	if len(matchedErrors) > 0 {
		findings = append(findings, engine.NewFinding(
			models.ModuleDisclosure,
			"DISC-VERBOSE-ERROR",
			host,
			"verbose-error",
			models.SeverityMedium,
			models.ConfidenceHigh,
			"Pesan Error Verbose / Stack Trace Terekspos pada Halaman",
			"Verbose Error Message / Stack Trace Disclosed in Page Response",
			"Respons halaman mengandung stack trace atau pesan error debug aplikasi.",
			"The HTTP response body contains raw application error messages or stack traces.",
			"Membocorkan struktur path kode sumber, query database, pustaka pihak ketiga, dan logika internal aplikasi.",
			"Exposes internal file paths, database query structures, library versions, and application logic.",
			"Nonaktifkan mode debug di produksi (`APP_DEBUG=false`, `DEBUG=False`, `display_errors=Off`) dan tampilkan halaman error generik kepada pengguna.",
			"Disable debug mode in production (`APP_DEBUG=false`, `DEBUG=False`, `display_errors=Off`) and serve generic error pages.",
			fmt.Sprintf("URL: %s\nPola Terdeteksi:\n- %s", targetURL, strings.Join(matchedErrors, "\n- ")),
			targetURL,
			"CWE-209",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://cwe.mitre.org/data/definitions/209.html"},
		))
	}

	// 5. Sensitive HTML Comments via golang.org/x/net/html
	if len(base.Body) > 0 {
		comments := extractSensitiveComments(base.Body)
		if len(comments) > 0 {
			findings = append(findings, engine.NewFinding(
				models.ModuleDisclosure,
				"DISC-HTML-COMMENTS",
				host,
				"html-comments",
				models.SeverityLow,
				models.ConfidenceMedium,
				fmt.Sprintf("Komentar HTML Mengandung Catatan Developer / Kata Kunci Sensitif (%d Komentar)", len(comments)),
				fmt.Sprintf("HTML Comments Contain Developer Notes or Sensitive Keywords (%d Comments)", len(comments)),
				"Ditemukan komentar HTML (`<!-- ... -->`) yang memuat catatan TODO/FIXME, endpoint internal, atau kata kunci sensitif.",
				"HTML comments (`<!-- ... -->`) containing developer notes (TODO/FIXME), internal paths, or sensitive keywords were found in the page source.",
				"Komentar di kode HTML produksi dapat membocorkan petunjuk arsitektur, kredensial sementara, atau fitur yang belum diamankan.",
				"Developer comments left in production HTML may leak architectural hints, staging URLs, or unfinished features.",
				"Hapus komentar pengembang dari template produksi atau gunakan minifier HTML pada proses build.",
				"Strip developer comments from production templates or enable HTML minification during the build pipeline.",
				strings.Join(comments, "\n"),
				targetURL,
				"CWE-615",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{"https://cwe.mitre.org/data/definitions/615.html"},
			))
		}
	}

	// 6. Check /.well-known/security.txt (RFC 9116)
	if ctx.Err() == nil {
		secTxtURL := scanCtx.Target.ResolvePath("/.well-known/security.txt")
		resp, body, err := scanCtx.Client.Get(ctx, secTxtURL, false)
		hasSecurityTxt := false
		if err == nil && resp != nil && resp.StatusCode == 200 {
			lowerTxt := strings.ToLower(string(body))
			if strings.Contains(lowerTxt, "contact:") {
				hasSecurityTxt = true
			}
		}
		if !hasSecurityTxt {
			findings = append(findings, engine.NewFinding(
				models.ModuleDisclosure,
				"DISC-NO-SECURITY-TXT",
				host,
				"no-security-txt",
				models.SeverityInfo,
				models.ConfidenceHigh,
				"File Kebijakan Pelaporan Kerentanan (/.well-known/security.txt) Tidak Ditemukan",
				"Missing Vulnerability Disclosure Policy File (/.well-known/security.txt)",
				"Website belum menyediakan file standar RFC 9116 `/.well-known/security.txt`.",
				"The website does not publish a standard RFC 9116 `/.well-known/security.txt` file.",
				"Peneliti keamanan yang menemukan celah mungkin kesulitan menghubungi tim keamanan organisasi secara tepat.",
				"Security researchers who discover vulnerabilities may lack a clear, standardized contact channel to report issues responsibly.",
				"Buat file `/.well-known/security.txt` berisi informasi `Contact:` dan `Expires:` sesuai standar RFC 9116.",
				"Publish a `/.well-known/security.txt` file containing `Contact:` and `Expires:` fields per RFC 9116.",
				fmt.Sprintf("URL Checked: %s (tidak ditemukan / missing `Contact:` field)", secTxtURL),
				secTxtURL,
				"CWE-1059",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{"https://securitytxt.org/", "https://datatracker.ietf.org/doc/html/rfc9116"},
			))
		}
	}

	return findings, nil
}

func extractSensitiveComments(body []byte) []string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	var matches []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.CommentNode {
			text := strings.TrimSpace(n.Data)
			lower := strings.ToLower(text)
			for _, kw := range commentSensitiveWords {
				if strings.Contains(lower, kw) {
					snippet := text
					if len(snippet) > 140 {
						snippet = snippet[:140] + "..."
					}
					matches = append(matches, fmt.Sprintf("<!-- %s -->", snippet))
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if len(matches) >= 5 {
				return
			}
			walk(c)
		}
	}
	walk(doc)
	return matches
}
