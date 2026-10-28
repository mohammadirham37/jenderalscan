package modules

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
)

// HeadersModule inspects HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
type HeadersModule struct{}

func NewHeadersModule() *HeadersModule {
	return &HeadersModule{}
}

func (m *HeadersModule) ID() models.ModuleID {
	return models.ModuleHeaders
}

func (m *HeadersModule) Name() string {
	return "Security Headers"
}

func (m *HeadersModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
	base := scanCtx.Baseline
	if base == nil {
		var err error
		base, err = scanCtx.Client.FetchBaseline(ctx)
		if err != nil {
			return nil, fmt.Errorf("gagal mengambil respons HTTP: %w", err)
		}
	}
	if base == nil {
		return nil, errors.New("respons HTTP kosong")
	}

	headers := base.Headers
	host := scanCtx.Target.Hostname
	targetURL := base.FinalURL
	if targetURL == "" {
		targetURL = scanCtx.Target.NormalizedURL
	}

	var findings []models.Finding

	// 1. Strict-Transport-Security (HSTS)
	hsts := strings.TrimSpace(headers.Get("Strict-Transport-Security"))
	if hsts == "" {
		sev := models.SeverityMedium
		if scanCtx.Target.Scheme == "http" && !strings.HasPrefix(targetURL, "https://") {
			sev = models.SeverityMedium
		}
		findings = append(findings, engine.NewFinding(
			models.ModuleHeaders,
			"HDR-HSTS-MISSING",
			host,
			"hsts-missing",
			sev,
			models.ConfidenceHigh,
			"Header Strict-Transport-Security (HSTS) Tidak Ditemukan",
			"Missing Strict-Transport-Security (HSTS) Header",
			"Header HTTP Strict-Transport-Security (HSTS) tidak dikirim oleh server. HSTS menginstruksikan browser agar hanya berkomunikasi dengan website melalui koneksi HTTPS terenkripsi.",
			"The HTTP Strict-Transport-Security (HSTS) response header is missing. HSTS instructs browsers to only communicate with the site over encrypted HTTPS connections.",
			"Tanpa HSTS, pengguna rentan terhadap serangan SSL stripping (seperti man-in-the-middle pada jaringan publik) ketika mengakses domain melalui HTTP pertama kali.",
			"Without HSTS, users are vulnerable to SSL stripping and downgrade attacks (such as Man-in-the-Middle on untrusted networks) on their initial HTTP request.",
			"Tambahkan header respons `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` pada semua respons HTTPS.",
			"Add the response header `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on all HTTPS responses.",
			fmt.Sprintf("URL: %s\nStatus: %s\nStrict-Transport-Security: <tidak ada / missing>", targetURL, base.Status),
			targetURL,
			"CWE-319",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{
				"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
				"https://cwe.mitre.org/data/definitions/319.html",
			},
		))
	} else {
		maxAge := parseHSTSMaxAge(hsts)
		if maxAge >= 0 && maxAge < 31536000 {
			findings = append(findings, engine.NewFinding(
				models.ModuleHeaders,
				"HDR-HSTS-WEAK",
				host,
				"hsts-weak",
				models.SeverityLow,
				models.ConfidenceHigh,
				"Durasi max-age HSTS Terlalu Singkat (< 1 Tahun)",
				"Weak HSTS max-age Duration (< 1 Year)",
				fmt.Sprintf("Header Strict-Transport-Security ditemukan namun nilai max-age (%d detik) kurang dari rekomendasi minimum 1 tahun (31.536.000 detik).", maxAge),
				fmt.Sprintf("The Strict-Transport-Security header is present, but its max-age (%d seconds) is shorter than the recommended 1 year (31,536,000 seconds).", maxAge),
				"Durasi HSTS yang pendek membuka celah bagi penyerang untuk melakukan downgrade ke HTTP apabila pengguna tidak mengunjungi situs dalam periode tersebut.",
				"A short HSTS duration leaves a window for attackers to perform HTTP downgrade attacks if a user has not visited the site recently.",
				"Tingkatkan nilai `max-age` minimal menjadi `31536000` (1 tahun) dan pertimbangkan direktif `includeSubDomains`.",
				"Increase `max-age` to at least `31536000` (1 year) and consider adding `includeSubDomains`.",
				fmt.Sprintf("Strict-Transport-Security: %s", hsts),
				targetURL,
				"CWE-319",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{
					"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
				},
			))
		}
	}

	// 2. Content-Security-Policy (CSP)
	csp := strings.TrimSpace(headers.Get("Content-Security-Policy"))
	if csp == "" {
		findings = append(findings, engine.NewFinding(
			models.ModuleHeaders,
			"HDR-CSP-MISSING",
			host,
			"csp-missing",
			models.SeverityMedium,
			models.ConfidenceHigh,
			"Header Content-Security-Policy (CSP) Tidak Ditemukan",
			"Missing Content-Security-Policy (CSP) Header",
			"Server tidak mengirimkan header Content-Security-Policy (CSP). CSP membatasi sumber daya (script, style, frame, koneksi) yang diizinkan dimuat oleh browser.",
			"The server did not return a Content-Security-Policy (CSP) header. CSP restricts the origins of scripts, styles, frames, and connections that the browser is allowed to load.",
			"Tanpa CSP, dampak kerentanan Cross-Site Scripting (XSS) dan injeksi konten pihak ketiga meningkat drastis karena browser tidak memiliki pembatasan eksekusi skrip.",
			"Without CSP, any Cross-Site Scripting (XSS) or data injection vulnerability can execute arbitrary scripts and exfiltrate sensitive session data without browser-level mitigation.",
			"Terapkan kebijakan Content-Security-Policy yang ketat, misalnya: `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`.",
			"Define a restrictive Content-Security-Policy header, e.g., `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`.",
			fmt.Sprintf("URL: %s\nContent-Security-Policy: <tidak ada / missing>", targetURL),
			targetURL,
			"CWE-693",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{
				"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
				"https://cwe.mitre.org/data/definitions/693.html",
			},
		))
	} else {
		lowerCSP := strings.ToLower(csp)
		var weakDirectives []string
		if strings.Contains(lowerCSP, "'unsafe-inline'") {
			weakDirectives = append(weakDirectives, "'unsafe-inline'")
		}
		if strings.Contains(lowerCSP, "'unsafe-eval'") {
			weakDirectives = append(weakDirectives, "'unsafe-eval'")
		}
		if len(weakDirectives) > 0 {
			findings = append(findings, engine.NewFinding(
				models.ModuleHeaders,
				"HDR-CSP-UNSAFE",
				host,
				"csp-unsafe",
				models.SeverityLow,
				models.ConfidenceHigh,
				"Content-Security-Policy Mengandung Direktif Tidak Aman ("+strings.Join(weakDirectives, ", ")+")",
				"Content-Security-Policy Contains Unsafe Directives ("+strings.Join(weakDirectives, ", ")+")",
				fmt.Sprintf("Header CSP ditemukan namun mengizinkan direktif %s yang melemahkan perlindungan terhadap XSS.", strings.Join(weakDirectives, " dan ")),
				fmt.Sprintf("A Content-Security-Policy header is present but allows %s, which weakens protection against XSS.", strings.Join(weakDirectives, " and ")),
				"Penggunaan `'unsafe-inline'` atau `'unsafe-eval'` memungkinkan penyerang mengeksekusi inline script atau evaluasi string sebagai kode jika terdapat celah injeksi HTML.",
				"Using `'unsafe-inline'` or `'unsafe-eval'` allows attackers to execute injected inline scripts or evaluate strings as code if an HTML injection flaw exists.",
				"Gunakan mekanisme CSP berbasis cryptographic `nonce` atau `sha256` hash dan hapus `'unsafe-inline'` serta `'unsafe-eval'` dari `script-src`.",
				"Migrate inline scripts to external files or use cryptographic CSP nonces/hashes, removing `'unsafe-inline'` and `'unsafe-eval'` from `script-src`.",
				fmt.Sprintf("Content-Security-Policy: %s", csp),
				targetURL,
				"CWE-693",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{
					"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
				},
			))
		}
	}

	// 3. X-Frame-Options / frame-ancestors (Clickjacking protection)
	xfo := strings.TrimSpace(headers.Get("X-Frame-Options"))
	hasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")
	if xfo == "" && !hasFrameAncestors {
		findings = append(findings, engine.NewFinding(
			models.ModuleHeaders,
			"HDR-XFO-MISSING",
			host,
			"xfo-missing",
			models.SeverityMedium,
			models.ConfidenceHigh,
			"Perlindungan Clickjacking (X-Frame-Options / frame-ancestors) Tidak Ditemukan",
			"Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
			"Server tidak mengirimkan header `X-Frame-Options` maupun direktif CSP `frame-ancestors`.",
			"The server neither sets the `X-Frame-Options` header nor specifies a `frame-ancestors` directive in `Content-Security-Policy`.",
			"Halaman web dapat disematkan di dalam `<iframe>` pada situs jahat untuk melakukan serangan Clickjacking (UI Redressing), menipu pengguna agar mengklik tombol sensitif.",
			"Pages can be framed inside an `<iframe>` on a malicious site to conduct Clickjacking (UI Redressing) attacks, tricking users into performing unintended actions.",
			"Tambahkan header `X-Frame-Options: DENY` (atau `SAMEORIGIN`) serta direktif CSP `frame-ancestors 'none'` (atau `'self'`).",
			"Add the `X-Frame-Options: DENY` (or `SAMEORIGIN`) header and include `frame-ancestors 'none'` (or `'self'`) in your CSP.",
			fmt.Sprintf("URL: %s\nX-Frame-Options: <tidak ada>\nCSP frame-ancestors: <tidak ada>", targetURL),
			targetURL,
			"CWE-1021",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{
				"https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
				"https://cwe.mitre.org/data/definitions/1021.html",
			},
		))
	} else if xfo != "" {
		upperXFO := strings.ToUpper(xfo)
		if upperXFO != "DENY" && upperXFO != "SAMEORIGIN" {
			findings = append(findings, engine.NewFinding(
				models.ModuleHeaders,
				"HDR-XFO-INVALID",
				host,
				"xfo-invalid",
				models.SeverityLow,
				models.ConfidenceHigh,
				"Nilai X-Frame-Options Tidak Standar atau Usang",
				"Non-Standard or Deprecated X-Frame-Options Value",
				fmt.Sprintf("Header `X-Frame-Options` bernilai `%s`, bukan `DENY` atau `SAMEORIGIN`.", xfo),
				fmt.Sprintf("The `X-Frame-Options` header is set to `%s`, which is neither `DENY` nor `SAMEORIGIN`.", xfo),
				"Direktif seperti `ALLOW-FROM` sudah tidak didukung oleh browser modern sehingga perlindungan Clickjacking menjadi tidak efektif.",
				"Directives such as `ALLOW-FROM` are deprecated and ignored by modern browsers, leaving the page unprotected against Clickjacking.",
				"Gunakan `X-Frame-Options: DENY` atau `SAMEORIGIN`, dan gunakan CSP `frame-ancestors` untuk daftar domain tertentu.",
				"Use `X-Frame-Options: DENY` or `SAMEORIGIN`, and use CSP `frame-ancestors` if specific origins must be allowed.",
				fmt.Sprintf("X-Frame-Options: %s", xfo),
				targetURL,
				"CWE-1021",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"},
			))
		}
	}

	// 4. X-Content-Type-Options
	xcto := strings.TrimSpace(headers.Get("X-Content-Type-Options"))
	if !strings.EqualFold(xcto, "nosniff") {
		findings = append(findings, engine.NewFinding(
			models.ModuleHeaders,
			"HDR-XCTO-MISSING",
			host,
			"xcto-missing",
			models.SeverityLow,
			models.ConfidenceHigh,
			"Header X-Content-Type-Options: nosniff Tidak Ditemukan",
			"Missing X-Content-Type-Options: nosniff Header",
			"Header `X-Content-Type-Options: nosniff` tidak diatur pada respons HTTP.",
			"The `X-Content-Type-Options: nosniff` header is missing from the HTTP response.",
			"Browser dapat melakukan MIME-sniffing dan mengeksekusi file yang diunggah pengguna (mis. gambar atau teks) sebagai HTML atau JavaScript berbahaya.",
			"Browsers may perform MIME-type sniffing and execute user-uploaded non-script files (such as images or text) as executable HTML or JavaScript.",
			"Tambahkan header respons `X-Content-Type-Options: nosniff` secara global pada web server atau reverse proxy.",
			"Set the response header `X-Content-Type-Options: nosniff` globally on your web server or reverse proxy.",
			engine.FormatHeaderEvidence("X-Content-Type-Options", xcto),
			targetURL,
			"CWE-693",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
				"https://cwe.mitre.org/data/definitions/693.html",
			},
		))
	}

	// 5. Referrer-Policy
	refPolicy := strings.TrimSpace(headers.Get("Referrer-Policy"))
	if refPolicy == "" {
		findings = append(findings, engine.NewFinding(
			models.ModuleHeaders,
			"HDR-REFERRER-MISSING",
			host,
			"referrer-missing",
			models.SeverityLow,
			models.ConfidenceHigh,
			"Header Referrer-Policy Tidak Ditemukan",
			"Missing Referrer-Policy Header",
			"Header `Referrer-Policy` tidak ditemukan pada respons HTTP.",
			"The `Referrer-Policy` header is not present in the HTTP response.",
			"Parameter URL sensitif (seperti token reset, session ID di query string, atau path internal) dapat bocor melalui header `Referer` ke situs pihak ketiga.",
			"Sensitive URL parameters or internal paths may leak via the `Referer` header when users navigate to external websites or load third-party assets.",
			"Tambahkan header `Referrer-Policy: strict-origin-when-cross-origin` atau `no-referrer`.",
			"Add the header `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
			engine.FormatHeaderEvidence("Referrer-Policy", refPolicy),
			targetURL,
			"CWE-200",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"},
		))
	} else if strings.Contains(strings.ToLower(refPolicy), "unsafe-url") {
		findings = append(findings, engine.NewFinding(
			models.ModuleHeaders,
			"HDR-REFERRER-UNSAFE",
			host,
			"referrer-unsafe",
			models.SeverityLow,
			models.ConfidenceHigh,
			"Referrer-Policy Mengizinkan Kebijakan Tidak Aman (unsafe-url)",
			"Unsafe Referrer-Policy Configuration (unsafe-url)",
			fmt.Sprintf("Header `Referrer-Policy` diset ke `%s`, yang mengirimkan URL lengkap beserta query string ke semua origin termasuk HTTP tidak terenkripsi.", refPolicy),
			fmt.Sprintf("The `Referrer-Policy` header is set to `%s`, which sends the full URL including query parameters to all origins, even over plaintext HTTP.", refPolicy),
			"Informasi sensitif pada URL atau parameter query dapat bocor ke server eksternal.",
			"Sensitive path and query string parameters can leak to third-party servers.",
			"Ubah `Referrer-Policy` menjadi `strict-origin-when-cross-origin` atau `same-origin`.",
			"Change `Referrer-Policy` to `strict-origin-when-cross-origin` or `same-origin`.",
			fmt.Sprintf("Referrer-Policy: %s", refPolicy),
			targetURL,
			"CWE-200",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"},
		))
	}

	// 6. Permissions-Policy
	permPolicy := strings.TrimSpace(headers.Get("Permissions-Policy"))
	if permPolicy == "" {
		findings = append(findings, engine.NewFinding(
			models.ModuleHeaders,
			"HDR-PERMISSIONS-MISSING",
			host,
			"permissions-missing",
			models.SeverityLow,
			models.ConfidenceHigh,
			"Header Permissions-Policy Tidak Ditemukan",
			"Missing Permissions-Policy Header",
			"Header `Permissions-Policy` tidak ditemukan. Header ini membatasi akses fitur API browser sensitif seperti kamera, mikrofon, geolokasi, dan pembayaran.",
			"The `Permissions-Policy` header is missing. This header restricts access to sensitive browser APIs such as camera, microphone, geolocation, and payment.",
			"Tanpa batasan eksplisit, iframe pihak ketiga atau kode injeksi dapat mencoba meminta izin fitur perangkat keras sensitif pada konteks origin situs.",
			"Without explicit restrictions, embedded third-party frames or injected scripts may request access to sensitive browser features within the site's origin context.",
			"Tambahkan header `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` sesuai kebutuhan aplikasi.",
			"Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` tailored to the features your application actually needs.",
			engine.FormatHeaderEvidence("Permissions-Policy", permPolicy),
			targetURL,
			"CWE-693",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"},
		))
	}

	// 7. Cross-Origin-Opener-Policy (COOP)
	coop := strings.TrimSpace(headers.Get("Cross-Origin-Opener-Policy"))
	if coop == "" {
		findings = append(findings, engine.NewFinding(
			models.ModuleHeaders,
			"HDR-COOP-MISSING",
			host,
			"coop-missing",
			models.SeverityInfo,
			models.ConfidenceHigh,
			"Header Isolasi Cross-Origin (Cross-Origin-Opener-Policy) Tidak Ditemukan",
			"Missing Cross-Origin-Opener-Policy (COOP) Header",
			"Header `Cross-Origin-Opener-Policy` tidak diset untuk mengisolasi browsing context jendela top-level.",
			"The `Cross-Origin-Opener-Policy` header is not configured to isolate the top-level browsing context.",
			"Dokumen yang dibuka di tab baru dapat berbagi grup konteks dengan dokumen lintas origin (serangan XS-Leaks / tabnabbing).",
			"Cross-origin popups or tabs may share a browsing context group with the application, enabling potential XS-Leaks or window reference attacks.",
			"Pertimbangkan menambahkan `Cross-Origin-Opener-Policy: same-origin`.",
			"Consider setting `Cross-Origin-Opener-Policy: same-origin`.",
			engine.FormatHeaderEvidence("Cross-Origin-Opener-Policy", coop),
			targetURL,
			"CWE-693",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"},
		))
	}

	return findings, nil
}

func parseHSTSMaxAge(headerVal string) int64 {
	parts := strings.Split(headerVal, ";")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "max-age") {
			val := strings.Trim(strings.TrimSpace(kv[1]), "\"'")
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				return n
			}
		}
	}
	return -1
}
