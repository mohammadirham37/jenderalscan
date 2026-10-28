package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
)

// CORSModule tests for overly permissive Cross-Origin Resource Sharing (CORS) configurations.
type CORSModule struct{}

func NewCORSModule() *CORSModule {
	return &CORSModule{}
}

func (m *CORSModule) ID() models.ModuleID {
	return models.ModuleCORS
}

func (m *CORSModule) Name() string {
	return "Konfigurasi CORS"
}

func (m *CORSModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
	host := scanCtx.Target.Hostname
	targetURL := scanCtx.Target.NormalizedURL
	if scanCtx.Baseline != nil && scanCtx.Baseline.FinalURL != "" {
		targetURL = scanCtx.Baseline.FinalURL
	}

	var findings []models.Finding

	// Probe 1: Arbitrary external Origin reflection
	arbitraryOrigin := "https://cors-audit.jenderalscan.invalid"
	acao, acac, err := m.sendOriginProbe(ctx, scanCtx, targetURL, arbitraryOrigin)
	if err == nil && acao != "" {
		if strings.EqualFold(acao, arbitraryOrigin) {
			sev := models.SeverityMedium
			ruleID := "CORS-ARBITRARY-ORIGIN"
			titleID := "CORS Memantulkan Origin Sembarang (Arbitrary Origin Reflection)"
			titleEN := "CORS Reflects Arbitrary Origin Header"
			if strings.EqualFold(acac, "true") {
				sev = models.SeverityHigh
				ruleID = "CORS-ARBITRARY-ORIGIN-CREDS"
				titleID = "CORS Memantulkan Origin Sembarang dengan Allow-Credentials: true"
				titleEN = "CORS Reflects Arbitrary Origin with Allow-Credentials: true"
			}
			findings = append(findings, engine.NewFinding(
				models.ModuleCORS,
				ruleID,
				host,
				ruleID,
				sev,
				models.ConfidenceHigh,
				titleID,
				titleEN,
				fmt.Sprintf("Server memantulkan nilai header `Origin: %s` secara langsung ke dalam `Access-Control-Allow-Origin`.", arbitraryOrigin),
				fmt.Sprintf("The server directly reflects the untrusted `Origin: %s` request header into `Access-Control-Allow-Origin`.", arbitraryOrigin),
				"Situs pihak ketiga mana pun dapat membaca respons API/halaman lintas-origin dari browser pengguna (terutama berbahaya bila `Access-Control-Allow-Credentials: true` juga aktif).",
				"Any malicious third-party website can read cross-origin responses from the victim's browser session (critical when `Access-Control-Allow-Credentials: true` is also enabled).",
				"Gunakan daftar putih (allowlist) domain tepercaya secara ketat untuk validasi `Origin`, dan jangan pernah memantulkan header `Origin` secara membabi buta.",
				"Validate the `Origin` header against a strict allowlist of trusted domains instead of dynamically reflecting any incoming `Origin`.",
				fmt.Sprintf("Request Header -> Origin: %s\nResponse Header <- Access-Control-Allow-Origin: %s\nResponse Header <- Access-Control-Allow-Credentials: %s", arbitraryOrigin, acao, acac),
				targetURL,
				"CWE-942",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{
					"https://portswigger.net/web-security/cors",
					"https://cwe.mitre.org/data/definitions/942.html",
				},
			))
			return findings, nil
		}

		if acao == "*" && strings.EqualFold(acac, "true") {
			findings = append(findings, engine.NewFinding(
				models.ModuleCORS,
				"CORS-WILDCARD-CREDS",
				host,
				"cors-wildcard-creds",
				models.SeverityMedium,
				models.ConfidenceHigh,
				"Konfigurasi CORS Menggabungkan Wildcard (*) dengan Allow-Credentials: true",
				"CORS Combines Wildcard (*) Origin with Allow-Credentials: true",
				"Server mengirimkan `Access-Control-Allow-Origin: *` bersamaan dengan `Access-Control-Allow-Credentials: true`.",
				"The server responds with `Access-Control-Allow-Origin: *` alongside `Access-Control-Allow-Credentials: true`.",
				"Menunjukkan kesalahan konfigurasi kebijakan akses lintas-origin yang terlalu permisif pada endpoint aplikasi.",
				"Indicates an overly permissive and misconfigured cross-origin policy on the application endpoint.",
				"Hindari penggunaan wildcard `*` pada endpoint yang membutuhkan kredensial; tentukan daftar domain yang diizinkan secara spesifik.",
				"Do not combine wildcard `*` origins with credentialed requests; specify explicit trusted origins.",
				fmt.Sprintf("Access-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s", acao, acac),
				targetURL,
				"CWE-942",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials"},
			))
		}
	}

	// Probe 2: Null Origin check
	if ctx.Err() == nil {
		acaoNull, acacNull, err := m.sendOriginProbe(ctx, scanCtx, targetURL, "null")
		if err == nil && strings.EqualFold(acaoNull, "null") {
			sev := models.SeverityMedium
			if strings.EqualFold(acacNull, "true") {
				sev = models.SeverityHigh
			}
			findings = append(findings, engine.NewFinding(
				models.ModuleCORS,
				"CORS-NULL-ORIGIN",
				host,
				"cors-null-origin",
				sev,
				models.ConfidenceHigh,
				"CORS Mengizinkan Origin 'null' (Access-Control-Allow-Origin: null)",
				"CORS Trusts 'null' Origin (Access-Control-Allow-Origin: null)",
				"Server mengizinkan `Origin: null` pada kebijakan CORS.",
				"The server explicitly permits `Origin: null` in its CORS response headers.",
				"Penyerang dapat memicu request dengan `Origin: null` menggunakan `<iframe sandbox>` pada situs berbahaya untuk membaca data sensitif lintas-origin.",
				"Attackers can easily generate cross-origin requests with `Origin: null` using sandboxed iframes (`<iframe sandbox>`) to steal sensitive response data.",
				"Hapus `null` dari daftar Origin yang diizinkan pada konfigurasi CORS server.",
				"Remove `null` from the list of allowed CORS origins.",
				fmt.Sprintf("Request Header -> Origin: null\nResponse Header <- Access-Control-Allow-Origin: %s\nResponse Header <- Access-Control-Allow-Credentials: %s", acaoNull, acacNull),
				targetURL,
				"CWE-942",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{"https://portswigger.net/web-security/cors"},
			))
		}
	}

	// Probe 3: Prefix Origin Regex Bypass check (e.g. https://target.com.evil.invalid)
	if ctx.Err() == nil {
		prefixOrigin := fmt.Sprintf("%s://%s.evil.invalid", scanCtx.Target.Scheme, host)
		acaoPre, acacPre, err := m.sendOriginProbe(ctx, scanCtx, targetURL, prefixOrigin)
		if err == nil && strings.EqualFold(acaoPre, prefixOrigin) {
			sev := models.SeverityMedium
			if strings.EqualFold(acacPre, "true") {
				sev = models.SeverityHigh
			}
			findings = append(findings, engine.NewFinding(
				models.ModuleCORS,
				"CORS-PREFIX-BYPASS",
				host,
				"cors-prefix-bypass",
				sev,
				models.ConfidenceHigh,
				"Validasi Origin CORS Rentan terhadap Bypass Subdomain/Prefix",
				"CORS Origin Validation Vulnerable to Prefix/Subdomain Bypass",
				fmt.Sprintf("Server menerima `Origin: %s` karena validasi domain hanya memeriksa awalan (prefix) tanpa batas akhir domain.", prefixOrigin),
				fmt.Sprintf("The server accepted `Origin: %s`, indicating flawed prefix/regex validation on the `Origin` header.", prefixOrigin),
				"Penyerang dapat mendaftarkan domain yang diawali dengan nama host target untuk melewati pembatasan CORS.",
				"An attacker can register a lookalike domain starting with the target's hostname to bypass CORS restrictions.",
				"Lakukan pencocokan string eksak (exact match) terhadap daftar origin yang diizinkan.",
				"Perform exact string matching against a strict allowlist of full origin URLs.",
				fmt.Sprintf("Request Header -> Origin: %s\nResponse Header <- Access-Control-Allow-Origin: %s\nResponse Header <- Access-Control-Allow-Credentials: %s", prefixOrigin, acaoPre, acacPre),
				targetURL,
				"CWE-942",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{"https://portswigger.net/web-security/cors"},
			))
		}
	}

	return findings, nil
}

func (m *CORSModule) sendOriginProbe(ctx context.Context, scanCtx *engine.ScanContext, targetURL, originVal string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Origin", originVal)
	resp, _, err := scanCtx.Client.Do(ctx, req, false)
	if err != nil || resp == nil {
		return "", "", err
	}
	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))
	return acao, acac, nil
}
