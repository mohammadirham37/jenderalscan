package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
)

// CookiesModule inspects Secure, HttpOnly, and SameSite flags on response cookies.
type CookiesModule struct{}

func NewCookiesModule() *CookiesModule {
	return &CookiesModule{}
}

func (m *CookiesModule) ID() models.ModuleID {
	return models.ModuleCookies
}

func (m *CookiesModule) Name() string {
	return "Cookie Flags"
}

func (m *CookiesModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
	base := scanCtx.Baseline
	if base == nil {
		var err error
		base, err = scanCtx.Client.FetchBaseline(ctx)
		if err != nil {
			return nil, fmt.Errorf("gagal mengambil respons HTTP: %w", err)
		}
	}
	if base == nil || len(base.Cookies) == 0 {
		return nil, nil
	}

	host := scanCtx.Target.Hostname
	targetURL := base.FinalURL
	if targetURL == "" {
		targetURL = scanCtx.Target.NormalizedURL
	}

	seen := make(map[string]bool)
	var findings []models.Finding

	for i, c := range base.Cookies {
		if c == nil || c.Name == "" {
			continue
		}
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true

		rawLine := c.Raw
		if rawLine == "" && i < len(base.RawSetCookies) {
			rawLine = base.RawSetCookies[i]
		}
		if rawLine == "" {
			rawLine = c.String()
		}

		isSensitive := isSessionLikeCookie(c.Name)
		baseSev := models.SeverityLow
		if isSensitive {
			baseSev = models.SeverityMedium
		}

		// 1. Check Secure flag
		if !c.Secure {
			findings = append(findings, engine.NewFinding(
				models.ModuleCookies,
				"COOKIE-MISSING-SECURE",
				host,
				"cookie-secure-"+c.Name,
				baseSev,
				models.ConfidenceHigh,
				fmt.Sprintf("Cookie '%s' Tidak Memiliki Flag Secure", c.Name),
				fmt.Sprintf("Cookie '%s' Missing Secure Flag", c.Name),
				fmt.Sprintf("Cookie `%s` dikirim tanpa atribut `Secure`.", c.Name),
				fmt.Sprintf("The cookie `%s` is set without the `Secure` attribute.", c.Name),
				"Tanpa flag `Secure`, browser dapat mengirimkan cookie ini melalui koneksi HTTP tidak terenkripsi sehingga berisiko disadap di jaringan.",
				"Without the `Secure` flag, the browser may transmit this cookie over unencrypted HTTP requests, exposing it to network interception.",
				fmt.Sprintf("Tambahkan atribut `; Secure` saat menetapkan cookie `%s` di server.", c.Name),
				fmt.Sprintf("Add the `; Secure` attribute when setting the `%s` cookie on the server.", c.Name),
				fmt.Sprintf("Set-Cookie: %s", maskCookieValue(rawLine)),
				targetURL,
				"CWE-614",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{
					"https://owasp.org/www-community/controls/SecureCookieAttribute",
					"https://cwe.mitre.org/data/definitions/614.html",
				},
			))
		}

		// 2. Check HttpOnly flag
		if !c.HttpOnly {
			findings = append(findings, engine.NewFinding(
				models.ModuleCookies,
				"COOKIE-MISSING-HTTPONLY",
				host,
				"cookie-httponly-"+c.Name,
				baseSev,
				models.ConfidenceHigh,
				fmt.Sprintf("Cookie '%s' Tidak Memiliki Flag HttpOnly", c.Name),
				fmt.Sprintf("Cookie '%s' Missing HttpOnly Flag", c.Name),
				fmt.Sprintf("Cookie `%s` dikirim tanpa atribut `HttpOnly`.", c.Name),
				fmt.Sprintf("The cookie `%s` is set without the `HttpOnly` attribute.", c.Name),
				"Cookie tanpa `HttpOnly` dapat dibaca oleh JavaScript melalui `document.cookie`, sehingga mudah dicuri apabila terdapat celah Cross-Site Scripting (XSS).",
				"Cookies without `HttpOnly` can be accessed via `document.cookie` in JavaScript, allowing session hijacking if an XSS vulnerability occurs.",
				fmt.Sprintf("Tambahkan atribut `; HttpOnly` pada cookie `%s` kecuali cookie tersebut memang wajib dibaca oleh kode frontend.", c.Name),
				fmt.Sprintf("Add the `; HttpOnly` attribute to the `%s` cookie unless client-side JavaScript explicitly requires read access.", c.Name),
				fmt.Sprintf("Set-Cookie: %s", maskCookieValue(rawLine)),
				targetURL,
				"CWE-1004",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{
					"https://owasp.org/www-community/HttpOnly",
					"https://cwe.mitre.org/data/definitions/1004.html",
				},
			))
		}

		// 3. Check SameSite attribute
		rawLower := strings.ToLower(rawLine)
		hasSameSite := strings.Contains(rawLower, "samesite=")
		if !hasSameSite || c.SameSite == http.SameSiteDefaultMode {
			findings = append(findings, engine.NewFinding(
				models.ModuleCookies,
				"COOKIE-MISSING-SAMESITE",
				host,
				"cookie-samesite-"+c.Name,
				models.SeverityLow,
				models.ConfidenceHigh,
				fmt.Sprintf("Cookie '%s' Tidak Mendefinisikan Atribut SameSite", c.Name),
				fmt.Sprintf("Cookie '%s' Missing Explicit SameSite Attribute", c.Name),
				fmt.Sprintf("Cookie `%s` tidak menetapkan atribut `SameSite` (`Lax` atau `Strict`).", c.Name),
				fmt.Sprintf("The cookie `%s` does not explicitly specify a `SameSite` attribute (`Lax` or `Strict`).", c.Name),
				"Tanpa kebijakan `SameSite` eksplisit, perilaku pengiriman cookie lintas situs bergantung pada default browser dan dapat meningkatkan risiko Cross-Site Request Forgery (CSRF).",
				"Without an explicit `SameSite` attribute, cross-site cookie transmission relies on browser defaults and may increase exposure to Cross-Site Request Forgery (CSRF).",
				fmt.Sprintf("Tetapkan `; SameSite=Lax` atau `; SameSite=Strict` pada cookie `%s`.", c.Name),
				fmt.Sprintf("Set `; SameSite=Lax` or `; SameSite=Strict` on the `%s` cookie.", c.Name),
				fmt.Sprintf("Set-Cookie: %s", maskCookieValue(rawLine)),
				targetURL,
				"CWE-1275",
				"OWASP A01:2021 - Broken Access Control",
				[]string{
					"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value",
					"https://cwe.mitre.org/data/definitions/1275.html",
				},
			))
		} else if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			findings = append(findings, engine.NewFinding(
				models.ModuleCookies,
				"COOKIE-SAMESITE-NONE-INSECURE",
				host,
				"cookie-samesite-none-"+c.Name,
				models.SeverityMedium,
				models.ConfidenceHigh,
				fmt.Sprintf("Cookie '%s' Menggunakan SameSite=None Tanpa Flag Secure", c.Name),
				fmt.Sprintf("Cookie '%s' Uses SameSite=None Without Secure Flag", c.Name),
				fmt.Sprintf("Cookie `%s` diset dengan `SameSite=None` tetapi tidak menyertakan flag `Secure`.", c.Name),
				fmt.Sprintf("The cookie `%s` sets `SameSite=None` without the required `Secure` attribute.", c.Name),
				"Cookie dengan `SameSite=None` dikirim pada semua request lintas situs dan ditolak oleh browser modern jika tidak disertai `Secure`.",
				"Cookies with `SameSite=None` are sent on all cross-site requests and are rejected by modern browsers if `Secure` is omitted.",
				"Gunakan `SameSite=Lax` atau `SameSite=Strict`, atau tambahkan `; Secure` jika pengiriman lintas domain memang dibutuhkan.",
				"Use `SameSite=Lax` or `SameSite=Strict`, or add `; Secure` if cross-site usage is genuinely required.",
				fmt.Sprintf("Set-Cookie: %s", maskCookieValue(rawLine)),
				targetURL,
				"CWE-1275",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value"},
			))
		}
	}

	return findings, nil
}

func isSessionLikeCookie(name string) bool {
	lower := strings.ToLower(name)
	keywords := []string{"sess", "sid", "auth", "token", "jwt", "login", "user", "csrf", "xsrf", "laravel", "phpsessid", "jsessionid", "asp.net"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func maskCookieValue(raw string) string {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return raw
	}
	kv := strings.SplitN(parts[0], "=", 2)
	if len(kv) == 2 && len(kv[1]) > 8 {
		parts[0] = kv[0] + "=" + kv[1][:4] + "..." + kv[1][len(kv[1])-2:]
	}
	return strings.Join(parts, ";")
}
