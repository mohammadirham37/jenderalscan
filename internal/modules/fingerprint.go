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

// FingerprintModule identifies web servers, frameworks, CMS, programming languages/runtimes (PHP, Go, Rust, Node.js, Python, Java, .NET), libraries, and versions.
type FingerprintModule struct{}

func NewFingerprintModule() *FingerprintModule {
	return &FingerprintModule{}
}

func (m *FingerprintModule) ID() models.ModuleID {
	return models.ModuleFingerprint
}

func (m *FingerprintModule) Name() string {
	return "Tech Fingerprint"
}

type tokenPattern struct {
	regex       *regexp.Regexp
	name        string
	category    string
	language    string
	inferLang   string // if set, also registers the underlying language/runtime
}

var headerTokenPatterns = []tokenPattern{
	// Web Servers & Proxies
	{regexp.MustCompile(`(?i)\bnginx(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "nginx", "Web Server", "C", ""},
	{regexp.MustCompile(`(?i)\bApache(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Apache", "Web Server", "C", ""},
	{regexp.MustCompile(`(?i)\bMicrosoft-IIS(?:/([0-9]+\.[0-9]+))?`), "Microsoft-IIS", "Web Server", ".NET / C#", ""},
	{regexp.MustCompile(`(?i)\bLiteSpeed(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "LiteSpeed", "Web Server", "C++", ""},
	{regexp.MustCompile(`(?i)\bOpenSSL(?:/([0-9]+\.[0-9]+\.[0-9]+[a-z]?))?`), "OpenSSL", "Crypto Library", "C", ""},
	{regexp.MustCompile(`(?i)\bEnvoy\b`), "Envoy", "Reverse Proxy", "C++", ""},

	// PHP Ecosystem
	{regexp.MustCompile(`(?i)\bPHP(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "PHP", "Runtime", "PHP", ""},
	{regexp.MustCompile(`(?i)\bLaravel(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Laravel", "Framework", "PHP", "PHP"},
	{regexp.MustCompile(`(?i)\bSymfony(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Symfony", "Framework", "PHP", "PHP"},
	{regexp.MustCompile(`(?i)\bCodeIgniter(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "CodeIgniter", "Framework", "PHP", "PHP"},
	{regexp.MustCompile(`(?i)\bDrupal(?:\s+([0-9]+(?:\.[0-9]+)?))?`), "Drupal", "CMS", "PHP", "PHP"},

	// Go (Golang) Ecosystem
	{regexp.MustCompile(`(?i)\bCaddy(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Caddy", "Web Server", "Go", "Go"},
	{regexp.MustCompile(`(?i)\bfasthttp\b`), "Fasthttp", "HTTP Engine", "Go", "Go"},
	{regexp.MustCompile(`(?i)\bFiber(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Go Fiber", "Framework", "Go", "Go"},
	{regexp.MustCompile(`(?i)\bGin(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Gin", "Framework", "Go", "Go"},
	{regexp.MustCompile(`(?i)\bEcho(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Echo", "Framework", "Go", "Go"},
	{regexp.MustCompile(`(?i)\bTraefik(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Traefik", "Reverse Proxy", "Go", "Go"},
	{regexp.MustCompile(`(?i)\bMinIO\b`), "MinIO", "Object Storage", "Go", "Go"},

	// Rust Ecosystem
	{regexp.MustCompile(`(?i)\bactix-web(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Actix-web", "Framework", "Rust", "Rust"},
	{regexp.MustCompile(`(?i)\baxum(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Axum", "Framework", "Rust", "Rust"},
	{regexp.MustCompile(`(?i)\bhyper(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Hyper", "HTTP Engine", "Rust", "Rust"},
	{regexp.MustCompile(`(?i)\bRocket(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Rocket", "Framework", "Rust", "Rust"},
	{regexp.MustCompile(`(?i)\bwarp(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Warp", "Framework", "Rust", "Rust"},
	{regexp.MustCompile(`(?i)\bPingora(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Pingora", "Reverse Proxy", "Rust", "Rust"},
	{regexp.MustCompile(`(?i)\bdeno(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Deno", "Runtime", "Rust / TypeScript", "Rust"},

	// Node.js / JavaScript / TypeScript Ecosystem
	{regexp.MustCompile(`(?i)\bExpress\b`), "Express", "Framework", "Node.js", "Node.js"},
	{regexp.MustCompile(`(?i)\bNext\.js(?:\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Next.js", "Framework", "Node.js / React", "Node.js"},
	{regexp.MustCompile(`(?i)\bNuxt(?:\.js)?(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Nuxt.js", "Framework", "Node.js / Vue", "Node.js"},
	{regexp.MustCompile(`(?i)\bNestJS\b`), "NestJS", "Framework", "Node.js", "Node.js"},
	{regexp.MustCompile(`(?i)\bFastify(?:/v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Fastify", "Framework", "Node.js", "Node.js"},
	{regexp.MustCompile(`(?i)\bKoa\b`), "Koa", "Framework", "Node.js", "Node.js"},
	{regexp.MustCompile(`(?i)\bPhusion Passenger(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Phusion Passenger", "App Server", "Ruby / Node.js", ""},

	// Python Ecosystem
	{regexp.MustCompile(`(?i)\bPython(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Python", "Runtime", "Python", ""},
	{regexp.MustCompile(`(?i)\bWerkzeug(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Werkzeug", "WSGI / Flask", "Python", "Python"},
	{regexp.MustCompile(`(?i)\bgunicorn(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Gunicorn", "WSGI Server", "Python", "Python"},
	{regexp.MustCompile(`(?i)\buvicorn(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Uvicorn", "ASGI / FastAPI", "Python", "Python"},
	{regexp.MustCompile(`(?i)\bWSGIServer(?:/([0-9]+\.[0-9]+))?`), "Django WSGIServer", "WSGI Server", "Python", "Python"},
	{regexp.MustCompile(`(?i)\bTornadoServer(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Tornado", "Framework", "Python", "Python"},

	// Java / .NET / Ruby / Elixir Ecosystem
	{regexp.MustCompile(`(?i)\bASP\.NET\b`), "ASP.NET", "Framework", ".NET / C#", ""},
	{regexp.MustCompile(`(?i)\bKestrel\b`), "Kestrel", "Web Server", ".NET / C#", ".NET"},
	{regexp.MustCompile(`(?i)\bJetty\(([0-9]+\.[0-9]+(?:\.[0-9]+)?)\)`), "Jetty", "App Server", "Java", "Java"},
	{regexp.MustCompile(`(?i)\bTomcat(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Apache Tomcat", "App Server", "Java", "Java"},
	{regexp.MustCompile(`(?i)\bWildFly(?:/([0-9]+(?:\.[0-9]+)?))?`), "WildFly", "App Server", "Java", "Java"},
	{regexp.MustCompile(`(?i)\bPuma(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`), "Puma", "App Server", "Ruby", "Ruby"},
	{regexp.MustCompile(`(?i)\bcowboy\b`), "Cowboy", "Web Server", "Erlang / Elixir", "Elixir"},
}

var scriptVersionPatterns = []struct {
	regex    *regexp.Regexp
	name     string
	category string
	language string
}{
	{regexp.MustCompile(`(?i)jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js`), "jQuery", "JavaScript Library", "JavaScript"},
	{regexp.MustCompile(`(?i)jquery/([0-9]+\.[0-9]+\.[0-9]+)/jquery`), "jQuery", "JavaScript Library", "JavaScript"},
	{regexp.MustCompile(`(?i)bootstrap[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.(?:js|css)`), "Bootstrap", "UI Framework", "CSS / JS"},
	{regexp.MustCompile(`(?i)bootstrap/([0-9]+\.[0-9]+\.[0-9]+)/`), "Bootstrap", "UI Framework", "CSS / JS"},
	{regexp.MustCompile(`(?i)vue(?:@|[.-])([0-9]+\.[0-9]+\.[0-9]+)`), "Vue.js", "Frontend Framework", "JavaScript"},
	{regexp.MustCompile(`(?i)react(?:-dom)?(?:@|[.-])([0-9]+\.[0-9]+\.[0-9]+)`), "React", "Frontend Library", "JavaScript"},
	{regexp.MustCompile(`(?i)lodash[.-]([0-9]+\.[0-9]+\.[0-9]+)`), "Lodash", "JavaScript Library", "JavaScript"},
	{regexp.MustCompile(`(?i)moment[.-]([0-9]+\.[0-9]+\.[0-9]+)`), "Moment.js", "JavaScript Library", "JavaScript"},
	{regexp.MustCompile(`(?i)alpinejs(?:@|[/-])([0-9]+\.[0-9]+\.[0-9]+)`), "Alpine.js", "Frontend Library", "JavaScript"},
	{regexp.MustCompile(`(?i)htmx\.org(?:@|[/-])([0-9]+\.[0-9]+\.[0-9]+)`), "HTMX", "Frontend Library", "JavaScript"},
	{regexp.MustCompile(`(?i)tailwindcss(?:@|[/-])([0-9]+\.[0-9]+\.[0-9]+)`), "Tailwind CSS", "UI Framework", "CSS"},
	{regexp.MustCompile(`(?i)wp-(?:emoji-release|embed)\.min\.js\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), "WordPress", "CMS", "PHP"},
}

func addTechWithRuntime(scanCtx *engine.ScanContext, tech models.DetectedTech, inferRuntime string) {
	scanCtx.AddTechnology(tech)
	if inferRuntime != "" {
		scanCtx.AddTechnology(models.DetectedTech{
			Name:       inferRuntime,
			Category:   "Language / Runtime",
			Language:   inferRuntime,
			Confidence: "High",
			Source:     fmt.Sprintf("Inferred from %s (%s)", tech.Name, tech.Source),
		})
	}
}

func (m *FingerprintModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
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

	headers := base.Headers

	// 1. Inspect Server, X-Powered-By, X-Generator, Via headers
	for _, hdrName := range []string{"Server", "X-Powered-By", "X-Generator", "Via"} {
		val := strings.TrimSpace(headers.Get(hdrName))
		if val == "" {
			continue
		}
		matched := false
		for _, pat := range headerTokenPatterns {
			if m := pat.regex.FindStringSubmatch(val); len(m) > 0 {
				ver := ""
				if len(m) > 1 {
					ver = m[1]
				}
				addTechWithRuntime(scanCtx, models.DetectedTech{
					Name:       pat.name,
					Category:   pat.category,
					Language:   pat.language,
					Version:    ver,
					Confidence: "High",
					Source:     fmt.Sprintf("Header %s: %s", hdrName, val),
				}, pat.inferLang)
				matched = true
			}
		}
		if !matched && hdrName == "Server" {
			parts := strings.SplitN(strings.Fields(val)[0], "/", 2)
			ver := ""
			if len(parts) == 2 {
				ver = parts[1]
			}
			scanCtx.AddTechnology(models.DetectedTech{
				Name:       parts[0],
				Category:   "Web Server",
				Version:    ver,
				Confidence: "High",
				Source:     fmt.Sprintf("Header Server: %s", val),
			})
		}
	}

	// Specialized framework headers
	if aspVer := strings.TrimSpace(headers.Get("X-AspNet-Version")); aspVer != "" {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "ASP.NET",
			Category:   "Framework",
			Language:   ".NET / C#",
			Version:    aspVer,
			Confidence: "High",
			Source:     "Header X-AspNet-Version: " + aspVer,
		}, ".NET")
	}
	if headers.Get("X-Nextjs-Cache") != "" || headers.Get("X-Nextjs-Matched-Path") != "" {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "Next.js",
			Category:   "Framework",
			Language:   "Node.js / React",
			Confidence: "High",
			Source:     "Header X-Nextjs-Cache",
		}, "Node.js")
	}
	if headers.Get("X-Drupal-Cache") != "" || headers.Get("X-Drupal-Dynamic-Cache") != "" {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "Drupal",
			Category:   "CMS",
			Language:   "PHP",
			Confidence: "High",
			Source:     "Header X-Drupal-Cache",
		}, "PHP")
	}
	if headers.Get("X-Debug-Token") != "" || headers.Get("X-Debug-Token-Link") != "" {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "Symfony",
			Category:   "Framework",
			Language:   "PHP",
			Confidence: "High",
			Source:     "Header X-Debug-Token",
		}, "PHP")
	}
	if strings.Contains(headers.Get("Link"), "api.w.org") {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "WordPress",
			Category:   "CMS",
			Language:   "PHP",
			Confidence: "High",
			Source:     "Header Link: rel=https://api.w.org/",
		}, "PHP")
	}

	// 2. Detect CDN / WAF from headers
	if headers.Get("CF-Ray") != "" || strings.Contains(strings.ToLower(headers.Get("Server")), "cloudflare") {
		scanCtx.AddTechnology(models.DetectedTech{
			Name:       "Cloudflare",
			Category:   "CDN / WAF",
			Confidence: "High",
			Source:     "Header CF-Ray / Server",
		})
	}
	if headers.Get("X-Vercel-Id") != "" {
		scanCtx.AddTechnology(models.DetectedTech{
			Name:       "Vercel",
			Category:   "Cloud Platform",
			Confidence: "High",
			Source:     "Header X-Vercel-Id",
		})
	}
	if headers.Get("X-Amz-Cf-Id") != "" {
		scanCtx.AddTechnology(models.DetectedTech{
			Name:       "AWS CloudFront",
			Category:   "CDN / WAF",
			Confidence: "High",
			Source:     "Header X-Amz-Cf-Id",
		})
	}

	// 3. Detect Frameworks & Programming Languages from Cookie signatures
	for _, c := range base.Cookies {
		lowerName := strings.ToLower(c.Name)
		switch {
		case lowerName == "phpsessid":
			scanCtx.AddTechnology(models.DetectedTech{
				Name:       "PHP",
				Category:   "Language / Runtime",
				Language:   "PHP",
				Confidence: "High",
				Source:     "Cookie PHPSESSID",
			})
		case strings.Contains(lowerName, "laravel_session") || lowerName == "xsrf-token" || lowerName == "laravel_token":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "Laravel",
				Category:   "Framework",
				Language:   "PHP",
				Confidence: "High",
				Source:     "Cookie " + c.Name,
			}, "PHP")
		case lowerName == "ci_session" || lowerName == "ci_csrf_token":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "CodeIgniter",
				Category:   "Framework",
				Language:   "PHP",
				Confidence: "High",
				Source:     "Cookie " + c.Name,
			}, "PHP")
		case lowerName == "yii_csrf_token" || lowerName == "_csrf-frontend" || lowerName == "_csrf-backend":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "Yii Framework",
				Category:   "Framework",
				Language:   "PHP",
				Confidence: "High",
				Source:     "Cookie " + c.Name,
			}, "PHP")
		case strings.HasPrefix(lowerName, "wordpress_") || strings.HasPrefix(lowerName, "wp-settings-"):
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "WordPress",
				Category:   "CMS",
				Language:   "PHP",
				Confidence: "High",
				Source:     "Cookie " + c.Name,
			}, "PHP")
		case lowerName == "jsessionid":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "Spring Boot / Java Servlet",
				Category:   "Framework",
				Language:   "Java",
				Confidence: "High",
				Source:     "Cookie JSESSIONID",
			}, "Java")
		case lowerName == "csrftoken" || lowerName == "sessionid":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "Django",
				Category:   "Framework",
				Language:   "Python",
				Confidence: "Medium",
				Source:     "Cookie " + c.Name,
			}, "Python")
		case lowerName == "connect.sid":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "Express",
				Category:   "Framework",
				Language:   "Node.js",
				Confidence: "High",
				Source:     "Cookie connect.sid",
			}, "Node.js")
		case lowerName == "adonis-session":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "AdonisJS",
				Category:   "Framework",
				Language:   "Node.js",
				Confidence: "High",
				Source:     "Cookie adonis-session",
			}, "Node.js")
		case lowerName == "_rails_session" || strings.HasSuffix(lowerName, "_session") && headers.Get("X-Runtime") != "":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "Ruby on Rails",
				Category:   "Framework",
				Language:   "Ruby",
				Confidence: "High",
				Source:     "Cookie " + c.Name,
			}, "Ruby")
		case strings.HasPrefix(lowerName, ".aspnetcore."):
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "ASP.NET Core",
				Category:   "Framework",
				Language:   ".NET / C#",
				Confidence: "High",
				Source:     "Cookie " + c.Name,
			}, ".NET")
		case lowerName == "actix-session":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "Actix-web",
				Category:   "Framework",
				Language:   "Rust",
				Confidence: "High",
				Source:     "Cookie actix-session",
			}, "Rust")
		case lowerName == "i_like_gitea":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "Gitea",
				Category:   "Application",
				Language:   "Go",
				Confidence: "High",
				Source:     "Cookie i_like_gitea",
			}, "Go")
		case lowerName == "grafana_session":
			addTechWithRuntime(scanCtx, models.DetectedTech{
				Name:       "Grafana",
				Category:   "Application",
				Language:   "Go",
				Confidence: "High",
				Source:     "Cookie grafana_session",
			}, "Go")
		}
	}

	// 4. Parse HTML DOM & Body signatures for frameworks, languages, and asset versions
	if len(base.Body) > 0 {
		parseHTMLTechnologies(base.Body, scanCtx)
	}

	techs := scanCtx.GetTechnologies()
	if len(techs) == 0 {
		return nil, nil
	}

	var summaryLines []string
	for _, t := range techs {
		label := t.Name
		if t.Version != "" {
			label += " " + t.Version
		}
		langTag := ""
		if t.Language != "" {
			langTag = " · Bahasa/Ekosistem: " + t.Language
		}
		summaryLines = append(summaryLines, fmt.Sprintf("- [%s%s] %s (Sumber: %s)", t.Category, langTag, label, t.Source))
	}

	finding := engine.NewFinding(
		models.ModuleFingerprint,
		"FP-TECH-STACK",
		host,
		"tech-stack-summary",
		models.SeverityInfo,
		models.ConfidenceHigh,
		fmt.Sprintf("Terdeteksi %d Komponen Teknologi & Bahasa Pemrograman", len(techs)),
		fmt.Sprintf("Detected %d Technology & Language Stack Components", len(techs)),
		"Modul Tech Fingerprint mengidentifikasi bahasa pemrograman (PHP, Go, Rust, Node.js, Python, Java, .NET), web server, framework (Laravel, Next.js, Actix, Gin, dll.), CMS, dan pustaka dari header HTTP, cookie, serta pola DOM HTML.",
		"The Tech Fingerprint module identified programming languages (PHP, Go, Rust, Node.js, Python, Java, .NET), web servers, frameworks (Laravel, Next.js, Actix, Gin, etc.), CMS, and libraries from HTTP headers, cookies, and HTML DOM signatures.",
		"Identifikasi tumpukan teknologi dan versi software membantu memetakan potensi kerentanan publik (CVE) yang relevan dengan komponen tersebut.",
		"Identifying the technology stack and versions allows mapping exact and potential public CVEs applicable to those components.",
		"Sembunyikan banner versi detail pada produksi (`server_tokens off;` di Nginx, `ServerTokens Prod` di Apache, `expose_php = Off` di PHP) dan perbarui seluruh framework/pustaka secara berkala.",
		"Suppress verbose version banners in production (`server_tokens off;` in Nginx, `ServerTokens Prod` in Apache, `expose_php = Off` in PHP) and keep all frameworks and libraries updated.",
		strings.Join(summaryLines, "\n"),
		targetURL,
		"CWE-200",
		"OWASP A05:2021 - Security Misconfiguration",
		[]string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
		},
	)

	return []models.Finding{finding}, nil
}

func parseHTMLTechnologies(body []byte, scanCtx *engine.ScanContext) {
	bodyStr := string(body)

	// Fast body markers for SSR / SPA / Backend frameworks
	if strings.Contains(bodyStr, "__NEXT_DATA__") || strings.Contains(bodyStr, "/_next/static/") {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "Next.js",
			Category:   "Framework",
			Language:   "Node.js / React",
			Confidence: "High",
			Source:     "HTML Marker __NEXT_DATA__ / /_next/static/",
		}, "Node.js")
	}
	if strings.Contains(bodyStr, "window.__NUXT__") || strings.Contains(bodyStr, "/_nuxt/") {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "Nuxt.js",
			Category:   "Framework",
			Language:   "Node.js / Vue",
			Confidence: "High",
			Source:     "HTML Marker __NUXT__ / /_nuxt/",
		}, "Node.js")
	}
	if strings.Contains(bodyStr, "window.__remixContext") {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "Remix",
			Category:   "Framework",
			Language:   "Node.js / React",
			Confidence: "High",
			Source:     "HTML Marker window.__remixContext",
		}, "Node.js")
	}
	if strings.Contains(bodyStr, "__sveltekit") {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "SvelteKit",
			Category:   "Framework",
			Language:   "Node.js / Svelte",
			Confidence: "High",
			Source:     "HTML Marker __sveltekit",
		}, "Node.js")
	}
	if strings.Contains(bodyStr, "wire:id=") || strings.Contains(bodyStr, "wire:snapshot=") || strings.Contains(bodyStr, "/livewire/livewire") {
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "Laravel Livewire",
			Category:   "Full-Stack Framework",
			Language:   "PHP",
			Confidence: "High",
			Source:     "HTML Attribute wire:id /wire:snapshot / livewire.js",
		}, "PHP")
		addTechWithRuntime(scanCtx, models.DetectedTech{
			Name:       "Laravel",
			Category:   "Framework",
			Language:   "PHP",
			Confidence: "High",
			Source:     "Inferred from Laravel Livewire",
		}, "PHP")
	}

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return
	}

	metaGenRegex := regexp.MustCompile(`(?i)^(WordPress|Joomla!?|Drupal|Hugo|Gatsby|Next\.js|Astro|Ghost|Zola|MediaWiki|Laravel)\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?`)

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			if tag == "astro-island" {
				scanCtx.AddTechnology(models.DetectedTech{
					Name:       "Astro",
					Category:   "Framework",
					Language:   "Node.js / TypeScript",
					Confidence: "High",
					Source:     "Element <astro-island>",
				})
			}

			switch tag {
			case "meta":
				var nameAttr, contentAttr string
				for _, a := range n.Attr {
					switch strings.ToLower(a.Key) {
					case "name":
						nameAttr = a.Val
					case "content":
						contentAttr = a.Val
					}
				}
				if strings.EqualFold(nameAttr, "generator") && contentAttr != "" {
					if m := metaGenRegex.FindStringSubmatch(strings.TrimSpace(contentAttr)); len(m) > 0 {
						prod := strings.TrimSuffix(m[1], "!")
						ver := ""
						if len(m) > 2 {
							ver = m[2]
						}
						lang := ""
						infer := ""
						switch strings.ToLower(prod) {
						case "wordpress", "joomla", "drupal", "mediawiki", "laravel":
							lang = "PHP"
							infer = "PHP"
						case "hugo":
							lang = "Go"
							infer = "Go"
						case "zola":
							lang = "Rust"
							infer = "Rust"
						case "next.js", "gatsby", "astro", "ghost":
							lang = "Node.js"
							infer = "Node.js"
						}
						addTechWithRuntime(scanCtx, models.DetectedTech{
							Name:       prod,
							Category:   "CMS / Generator",
							Language:   lang,
							Version:    ver,
							Confidence: "High",
							Source:     fmt.Sprintf("<meta name=\"generator\" content=%q>", contentAttr),
						}, infer)
					} else {
						scanCtx.AddTechnology(models.DetectedTech{
							Name:       contentAttr,
							Category:   "Generator",
							Confidence: "Medium",
							Source:     "<meta name=\"generator\">",
						})
					}
				}
				if strings.EqualFold(nameAttr, "csrf-token") && contentAttr != "" && len(contentAttr) == 40 {
					// Laravel's standard 40-char alphanumeric <meta name="csrf-token">
					addTechWithRuntime(scanCtx, models.DetectedTech{
						Name:       "Laravel",
						Category:   "Framework",
						Language:   "PHP",
						Confidence: "Medium",
						Source:     "<meta name=\"csrf-token\"> (40-char token)",
					}, "PHP")
				}

			case "script", "link":
				for _, a := range n.Attr {
					key := strings.ToLower(a.Key)
					if key == "src" || key == "href" {
						val := a.Val
						for _, sp := range scriptVersionPatterns {
							if m := sp.regex.FindStringSubmatch(val); len(m) > 1 {
								infer := ""
								if sp.language == "PHP" {
									infer = "PHP"
								}
								addTechWithRuntime(scanCtx, models.DetectedTech{
									Name:       sp.name,
									Category:   sp.category,
									Language:   sp.language,
									Version:    m[1],
									Confidence: "High",
									Source:     fmt.Sprintf("Asset URL: %s", val),
								}, infer)
							}
						}
						if strings.Contains(val, "/wp-content/") || strings.Contains(val, "/wp-includes/") {
							addTechWithRuntime(scanCtx, models.DetectedTech{
								Name:       "WordPress",
								Category:   "CMS",
								Language:   "PHP",
								Confidence: "High",
								Source:     "Asset path /wp-content/",
							}, "PHP")
						}
						if strings.Contains(val, "/build/assets/app-") && (strings.HasSuffix(val, ".js") || strings.HasSuffix(val, ".css")) {
							addTechWithRuntime(scanCtx, models.DetectedTech{
								Name:       "Laravel (Vite Bundle)",
								Category:   "Framework",
								Language:   "PHP",
								Confidence: "Medium",
								Source:     "Asset path " + val,
							}, "PHP")
						}
					}
				}
			}

			// Inspect custom framework DOM attributes
			for _, a := range n.Attr {
				lowerKey := strings.ToLower(a.Key)
				switch {
				case lowerKey == "ng-version" && a.Val != "":
					scanCtx.AddTechnology(models.DetectedTech{
						Name:       "Angular",
						Category:   "Frontend Framework",
						Language:   "TypeScript",
						Version:    a.Val,
						Confidence: "High",
						Source:     fmt.Sprintf("Attribute ng-version=%q", a.Val),
					})
				case lowerKey == "data-page" && strings.Contains(a.Val, `"component"`):
					scanCtx.AddTechnology(models.DetectedTech{
						Name:       "Inertia.js",
						Category:   "Full-Stack Adapter",
						Language:   "PHP / JavaScript",
						Confidence: "High",
						Source:     "Attribute data-page (Inertia JSON)",
					})
				case lowerKey == "x-data":
					scanCtx.AddTechnology(models.DetectedTech{
						Name:       "Alpine.js",
						Category:   "Frontend Library",
						Language:   "JavaScript",
						Confidence: "High",
						Source:     "Attribute x-data",
					})
				case lowerKey == "hx-get" || lowerKey == "hx-post":
					scanCtx.AddTechnology(models.DetectedTech{
						Name:       "HTMX",
						Category:   "Frontend Library",
						Language:   "JavaScript",
						Confidence: "High",
						Source:     "Attribute " + lowerKey,
					})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
}
