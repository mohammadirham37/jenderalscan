package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
	"jenderalscan/internal/storage"
)

func TestAllScannerModulesAgainstVulnerableTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.Header().Set("X-Upstream", "192.168.10.45")

		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		w.Header().Add("Set-Cookie", "PHPSESSID=abc123456; Path=/")

		switch r.URL.Path {
		case "/.git/HEAD":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
			return
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("APP_ENV=production\nDB_PASSWORD=secret\n"))
			return
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
  <meta name="generator" content="WordPress 6.2.0">
  <script src="/js/jquery-3.4.1.min.js"></script>
</head>
<body>
  <!-- TODO: remove debug admin password -->
  <h1>Test App</h1>
</body>
</html>`))
			return
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	eng := engine.NewEngine(store)
	RegisterAll(eng, store)

	// 1. Verify mandatory authorization guardrail blocks unauthorized scan
	_, err = eng.ExecuteScan(context.Background(), models.ScanRequest{
		TargetURL:         srv.URL,
		Profile:           models.ProfileFull,
		AuthorizedConfirm: false,
	}, nil)
	if err == nil {
		t.Fatal("expected error when AuthorizedConfirm is false, got nil")
	}

	// 2. Run authorized Full scan
	res, err := eng.ExecuteScan(context.Background(), models.ScanRequest{
		TargetURL:         srv.URL,
		Profile:           models.ProfileFull,
		AuthorizedConfirm: true,
		AuthorizationNote: "Unit Test Scope",
	}, nil)
	if err != nil {
		t.Fatalf("ExecuteScan failed: %v", err)
	}

	if res.Status != "completed" {
		t.Fatalf("expected status completed, got %s", res.Status)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings, got 0")
	}
	if len(res.Technologies) < 3 {
		t.Fatalf("expected at least 3 detected technologies, got %d: %+v", len(res.Technologies), res.Technologies)
	}

	foundRules := make(map[string]bool)
	for _, f := range res.Findings {
		foundRules[f.RuleID] = true
	}

	expectedRules := []string{
		"HDR-HSTS-MISSING",
		"HDR-CSP-MISSING",
		"COOKIE-MISSING-SECURE",
		"COOKIE-MISSING-HTTPONLY",
		"PATH-GIT-HEAD",
		"PATH-ENV-FILE",
		"FP-TECH-STACK",
		"CVE-CVE-2021-41773",
		"CVE-CVE-2020-11022",
		"CORS-ARBITRARY-ORIGIN-CREDS",
		"DISC-VERBOSE-BANNER",
		"DISC-PRIVATE-IP-HEADER",
		"DISC-HTML-COMMENTS",
	}

	for _, rule := range expectedRules {
		if !foundRules[rule] {
			t.Errorf("expected rule %s to be detected, but it was missing (found: %v)", rule, foundRules)
		}
	}
}

func TestSPASoft404DoesNotTriggerFalsePositivePaths(t *testing.T) {
	// Simulate an SPA that returns 200 OK with index.html for every path
	spaHTML := `<!DOCTYPE html><html><head><title>SPA App</title></head><body><div id="root"></div></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(spaHTML))
	}))
	defer srv.Close()

	scope, err := engine.ParseAndValidateTarget(srv.URL, true)
	if err != nil {
		t.Fatalf("ParseAndValidateTarget: %v", err)
	}
	settings := models.DefaultSettings()
	settings.RateLimitRPS = 100
	client, err := engine.NewScopedClient(scope, settings)
	if err != nil {
		t.Fatalf("NewScopedClient: %v", err)
	}

	scanCtx := &engine.ScanContext{
		ScanID:   "spa-test",
		Target:   scope,
		Client:   client,
		Settings: settings,
		Profile:  models.ProfileFull,
	}

	pathMod := NewPathsModule()
	findings, err := pathMod.Run(context.Background(), scanCtx)
	if err != nil {
		t.Fatalf("PathsModule.Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 false positive findings on SPA catch-all server, got %d: %+v", len(findings), findings)
	}
}

func TestTLSModuleDetectsSelfSignedCert(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()

	scope, err := engine.ParseAndValidateTarget(tlsSrv.URL, true)
	if err != nil {
		t.Fatalf("ParseAndValidateTarget: %v", err)
	}
	settings := models.DefaultSettings()
	client, err := engine.NewScopedClient(scope, settings)
	if err != nil {
		t.Fatalf("NewScopedClient: %v", err)
	}

	scanCtx := &engine.ScanContext{
		ScanID:   "tls-test",
		Target:   scope,
		Client:   client,
		Settings: settings,
		Profile:  models.ProfileQuick,
	}

	tlsMod := NewTLSModule()
	findings, err := tlsMod.Run(context.Background(), scanCtx)
	if err != nil {
		t.Fatalf("TLSModule.Run failed: %v", err)
	}

	hasSelfSigned := false
	hasSummary := false
	for _, f := range findings {
		if f.RuleID == "TLS-CERT-SELFSIGNED" {
			hasSelfSigned = true
		}
		if f.RuleID == "TLS-INFO-SUMMARY" {
			hasSummary = true
		}
	}
	if !hasSelfSigned || !hasSummary {
		t.Fatalf("expected TLS-CERT-SELFSIGNED and TLS-INFO-SUMMARY, got: %+v", findings)
	}
}

func TestDeepLanguageFingerprintAndEstimatedCVE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "actix-web")
		w.Header().Set("X-Powered-By", "Gin")
		w.Header().Add("Set-Cookie", "laravel_session=eyJpdiI6ImRlbW8ifQ; Path=/")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><div wire:id="123">Laravel Livewire + Go + Rust test</div></body></html>`))
	}))
	defer srv.Close()

	store, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	eng := engine.NewEngine(store)
	RegisterAll(eng, store)

	res, err := eng.ExecuteScan(context.Background(), models.ScanRequest{
		TargetURL:         srv.URL,
		Profile:           models.ProfileQuick,
		AuthorizedConfirm: true,
	}, nil)
	if err != nil {
		t.Fatalf("ExecuteScan failed: %v", err)
	}

	techNames := make(map[string]models.DetectedTech)
	for _, tech := range res.Technologies {
		techNames[tech.Name] = tech
	}

	for _, expected := range []string{"Laravel", "Laravel Livewire", "PHP", "Gin", "Go", "Actix-web", "Rust"} {
		if _, ok := techNames[expected]; !ok {
			t.Errorf("expected technology %q to be detected, got: %+v", expected, res.Technologies)
		}
	}

	if len(techNames["Laravel"].PotentialCVEs) == 0 {
		t.Errorf("expected Laravel to have estimated PotentialCVEs attached, got 0")
	}
	if len(techNames["Go"].PotentialCVEs) == 0 {
		t.Errorf("expected Go to have estimated PotentialCVEs attached, got 0")
	}
	if len(techNames["Rust"].PotentialCVEs) == 0 {
		t.Errorf("expected Rust to have estimated PotentialCVEs attached, got 0")
	}

	foundRules := make(map[string]bool)
	for _, f := range res.Findings {
		foundRules[f.RuleID] = true
	}
	for _, expectedRule := range []string{"CVE-ESTIMATE-LARAVEL", "CVE-ESTIMATE-GO", "CVE-ESTIMATE-RUST", "CVE-ESTIMATE-ACTIX-WEB"} {
		if !foundRules[expectedRule] {
			t.Errorf("expected estimated CVE rule %s to be generated, got rules: %v", expectedRule, foundRules)
		}
	}
}


