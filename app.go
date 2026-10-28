package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
	"jenderalscan/internal/modules"
	"jenderalscan/internal/report"
	"jenderalscan/internal/storage"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// ExportPayload is returned to the UI for one-click report downloads and local file saving.
type ExportPayload struct {
	Filename      string `json:"filename"`
	MimeType      string `json:"mimeType"`
	ContentBase64 string `json:"contentBase64"`
	SavedPath     string `json:"savedPath"`
}

// App struct binds the Go core to the Wails desktop GUI and HTTP bridge.
type App struct {
	ctx       context.Context
	isWails   bool
	store     *storage.Store
	engine    *engine.Engine
	cveMod    *modules.CVEModule

	mu             sync.RWMutex
	latestProgress *models.ScanProgressEvent
	sseClients     map[chan models.ScanProgressEvent]struct{}

	sandboxMu     sync.Mutex
	sandboxServer *http.Server
	sandboxURL    string
}

// NewApp creates and initializes the JenderalScan application core.
func NewApp(dbPath string) (*App, error) {
	store, err := storage.NewStore(dbPath)
	if err != nil {
		return nil, err
	}
	eng := engine.NewEngine(store)
	cveMod := modules.RegisterAll(eng, store)

	return &App{
		store:      store,
		engine:     eng,
		cveMod:     cveMod,
		sseClients: make(map[chan models.ScanProgressEvent]struct{}),
	}, nil
}

// startup is called when the Wails desktop app starts.
func (a *App) startup(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.isWails = true
	a.mu.Unlock()
}

// shutdown cleans up resources on exit.
func (a *App) shutdown(ctx context.Context) {
	a.sandboxMu.Lock()
	if a.sandboxServer != nil {
		_ = a.sandboxServer.Close()
	}
	a.sandboxMu.Unlock()

	if a.store != nil {
		_ = a.store.Close()
	}
}

func (a *App) emitProgress(ev models.ScanProgressEvent) {
	a.mu.Lock()
	evCopy := ev
	a.latestProgress = &evCopy
	wailsCtx := a.ctx
	isWails := a.isWails
	for ch := range a.sseClients {
		select {
		case ch <- evCopy:
		default:
		}
	}
	a.mu.Unlock()

	if isWails && wailsCtx != nil {
		wailsRuntime.EventsEmit(wailsCtx, "scan:progress", ev)
	}
}

// GetModules returns metadata for all 10 scanner modules.
func (a *App) GetModules() []models.ModuleInfo {
	return models.AllModules()
}

// GetSettings returns the current application configuration.
func (a *App) GetSettings() (models.AppSettings, error) {
	return a.store.GetSettings()
}

// SaveSettings updates and persists the application configuration.
func (a *App) SaveSettings(cfg models.AppSettings) (models.AppSettings, error) {
	if cfg.MaxWorkers < 1 {
		cfg.MaxWorkers = 1
	}
	if cfg.MaxWorkers > 25 {
		cfg.MaxWorkers = 25
	}
	if cfg.RateLimitRPS < 1 {
		cfg.RateLimitRPS = 1
	}
	if cfg.RateLimitRPS > 100 {
		cfg.RateLimitRPS = 100
	}
	if cfg.TimeoutSeconds < 2 {
		cfg.TimeoutSeconds = 2
	}
	if cfg.TimeoutSeconds > 60 {
		cfg.TimeoutSeconds = 60
	}
	if err := a.store.SaveSettings(cfg); err != nil {
		return cfg, err
	}
	return a.store.GetSettings()
}

// StartScan validates authorization and executes a scan, streaming progress events.
func (a *App) StartScan(req models.ScanRequest) (*models.ScanResult, error) {
	ctx := context.Background()
	res, err := a.engine.ExecuteScan(ctx, req, func(ev models.ScanProgressEvent) {
		a.emitProgress(ev)
	})
	return res, err
}

// CancelScan stops an active scan by ID.
func (a *App) CancelScan(scanID string) bool {
	if scanID == "" {
		a.mu.RLock()
		if a.latestProgress != nil {
			scanID = a.latestProgress.ScanID
		}
		a.mu.RUnlock()
	}
	return a.engine.CancelScan(scanID)
}

// GetLatestProgress returns the most recent progress snapshot for polling/initial hydration.
func (a *App) GetLatestProgress() *models.ScanProgressEvent {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.latestProgress
}

// GetScan retrieves a complete ScanResult by ID.
func (a *App) GetScan(scanID string) (*models.ScanResult, error) {
	return a.store.GetScan(scanID)
}

// ListScans returns all saved scan history records.
func (a *App) ListScans() ([]models.ScanResult, error) {
	return a.store.ListScans()
}

// DeleteScan deletes a single scan record by ID.
func (a *App) DeleteScan(scanID string) error {
	return a.store.DeleteScan(scanID)
}

// ClearHistory removes all scan history records.
func (a *App) ClearHistory() error {
	return a.store.ClearHistory()
}

// ListAuditLogs returns the accountability audit log entries.
func (a *App) ListAuditLogs() ([]models.AuditLogEntry, error) {
	return a.store.ListAuditLogs()
}

// GetCVEDatasetMeta returns metadata about the local CVE vulnerability dataset.
func (a *App) GetCVEDatasetMeta() models.CVEDatasetMeta {
	return a.cveMod.GetDatasetMeta()
}

// RefreshCVEDataset refreshes the local CVE dataset metadata and reloads custom rules.
func (a *App) RefreshCVEDataset() (models.CVEDatasetMeta, error) {
	return a.cveMod.RefreshDataset()
}

// ImportCVEDataset imports custom CVE definitions in JSON format into SQLite.
func (a *App) ImportCVEDataset(rawJSON string) (models.CVEDatasetMeta, error) {
	return a.cveMod.ImportCustomCVEs(rawJSON)
}

// ExportReport generates a JSON, HTML, or PDF report and saves a copy to the user's Downloads folder.
func (a *App) ExportReport(scanID string, format string) (*ExportPayload, error) {
	scan, err := a.store.GetScan(scanID)
	if err != nil {
		return nil, fmt.Errorf("scan tidak ditemukan: %w", err)
	}

	settings, _ := a.store.GetSettings()
	lang := settings.Language
	if lang == "" {
		lang = "id"
	}

	cleanHost := strings.ReplaceAll(scan.NormalizedHost, ":", "_")
	ts := scan.StartedAt.Format("20060102-150405")

	var data []byte
	var ext, mime string

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		data, err = report.ExportJSON(scan)
		ext = "json"
		mime = "application/json"
	case "md", "markdown":
		data, err = report.ExportMarkdown(scan, lang)
		ext = "md"
		mime = "text/markdown; charset=utf-8"
	case "html":
		data, err = report.ExportHTML(scan, lang)
		ext = "html"
		mime = "text/html"
	case "pdf":
		data, err = report.ExportPDF(scan, lang)
		ext = "pdf"
		mime = "application/pdf"
	default:
		return nil, fmt.Errorf("format laporan %q tidak didukung (gunakan json, md, html, atau pdf)", format)
	}
	if err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("jenderalscan-%s-%s.%s", cleanHost, ts, ext)
	savedPath := ""

	if home, err := os.UserHomeDir(); err == nil {
		dlDir := filepath.Join(home, "Downloads")
		if info, err := os.Stat(dlDir); err == nil && info.IsDir() {
			targetPath := filepath.Join(dlDir, filename)
			if err := os.WriteFile(targetPath, data, 0644); err == nil {
				savedPath = targetPath
			}
		}
	}

	return &ExportPayload{
		Filename:      filename,
		MimeType:      mime,
		ContentBase64: base64.StdEncoding.EncodeToString(data),
		SavedPath:     savedPath,
	}, nil
}

// StartSandboxTarget starts a local, safe, intentionally misconfigured HTTP server on 127.0.0.1 for testing & learning.
func (a *App) StartSandboxTarget() (string, error) {
	a.sandboxMu.Lock()
	defer a.sandboxMu.Unlock()

	if a.sandboxURL != "" {
		return a.sandboxURL, nil
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Intentionally vulnerable headers, cookies, CORS, and HTML for educational & scanner validation
		w.Header().Set("Server", "Apache/2.4.49 (Unix) OpenSSL/1.1.1k")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.Header().Set("X-Upstream-Node", "10.24.18.92:8080")

		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Set cookies without Secure / HttpOnly / SameSite
		w.Header().Add("Set-Cookie", "PHPSESSID=98a7b6c5d4e3f2a1; Path=/")
		w.Header().Add("Set-Cookie", "laravel_session=eyJpdiI6InNhbmRib3gifQ; Path=/")
		w.Header().Add("Set-Cookie", "auth_token=eyJhbGciOiJIUzI1NiJ9.sandbox; Path=/")

		switch r.URL.Path {
		case "/.git/HEAD":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
			return
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("APP_ENV=local_sandbox\nDB_HOST=127.0.0.1\nDB_PASSWORD=sandbox_demo_only\nSECRET_KEY=demo_secret_key\n"))
			return
		case "/phpinfo.php":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head><title>phpinfo()</title></head><body><h1>PHP Version 8.1.2</h1><p>Zend Engine v4.1.2</p></body></html>"))
			return
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin-panel\nDisallow: /backup-db\nDisallow: /config-internal\n"))
			return
		case "/swagger.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"Sandbox Internal API","version":"1.0"},"paths":{"/api/v1/users":{}}}`))
			return
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="generator" content="WordPress 6.3.1">
  <title>JenderalScan Local Sandbox Target</title>
  <script src="/assets/jquery-3.4.1.min.js"></script>
  <link rel="stylesheet" href="/assets/bootstrap-4.3.0.min.css">
</head>
<body>
  <!-- TODO: remove staging debug credentials before release (internal admin endpoint /staging-admin) -->
  <h1>JenderalScan Local Educational Target</h1>
  <p>Target lokal aman untuk menguji modul pemindaian JenderalScan.</p>
</body>
</html>`))
			return
		default:
			http.NotFound(w, r)
		}
	})

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	go func() {
		_ = srv.Serve(ln)
	}()

	a.sandboxServer = srv
	a.sandboxURL = fmt.Sprintf("http://%s", ln.Addr().String())
	return a.sandboxURL, nil
}

// registerAPIRoutes mounts HTTP & SSE endpoints for browser/development mode fallback.
func (a *App) registerAPIRoutes(mux *http.ServeMux) {
	writeJSON := func(w http.ResponseWriter, status int, payload any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
	}
	writeErr := func(w http.ResponseWriter, status int, err error) {
		writeJSON(w, status, map[string]string{"error": err.Error()})
	}

	mux.HandleFunc("/api/modules", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.GetModules())
	})

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var cfg models.AppSettings
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			saved, err := a.SaveSettings(cfg)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, saved)
			return
		}
		cfg, err := a.GetSettings()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	})

	mux.HandleFunc("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			id := r.URL.Query().Get("id")
			if id != "" {
				scan, err := a.GetScan(id)
				if err != nil {
					writeErr(w, http.StatusNotFound, err)
					return
				}
				writeJSON(w, http.StatusOK, scan)
				return
			}
			list, err := a.ListScans()
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var req models.ScanRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			res, err := a.StartScan(req)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, res)
		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			if id == "all" {
				if err := a.ClearHistory(); err != nil {
					writeErr(w, http.StatusInternalServerError, err)
					return
				}
			} else {
				if err := a.DeleteScan(id); err != nil {
					writeErr(w, http.StatusInternalServerError, err)
					return
				}
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}
	})

	mux.HandleFunc("/api/scans/cancel", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ScanID string `json:"scanId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ok := a.CancelScan(body.ScanID)
		writeJSON(w, http.StatusOK, map[string]bool{"cancelled": ok})
	})

	mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		scanID := r.URL.Query().Get("scanId")
		format := r.URL.Query().Get("format")
		payload, err := a.ExportReport(scanID, format)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, payload)
	})

	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		logs, err := a.ListAuditLogs()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, logs)
	})

	mux.HandleFunc("/api/cve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				Action  string `json:"action"`
				RawJSON string `json:"rawJson"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Action == "import" {
				meta, err := a.ImportCVEDataset(body.RawJSON)
				if err != nil {
					writeErr(w, http.StatusBadRequest, err)
					return
				}
				writeJSON(w, http.StatusOK, meta)
				return
			}
			meta, err := a.RefreshCVEDataset()
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, meta)
			return
		}
		writeJSON(w, http.StatusOK, a.GetCVEDatasetMeta())
	})

	mux.HandleFunc("/api/sandbox", func(w http.ResponseWriter, r *http.Request) {
		u, err := a.StartSandboxTarget()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"url": u})
	})

	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		ch := make(chan models.ScanProgressEvent, 16)
		a.mu.Lock()
		a.sseClients[ch] = struct{}{}
		a.mu.Unlock()
		defer func() {
			a.mu.Lock()
			delete(a.sseClients, ch)
			a.mu.Unlock()
		}()

		for {
			select {
			case <-r.Context().Done():
				return
			case ev := <-ch:
				raw, _ := json.Marshal(ev)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(raw))
				flusher.Flush()
			}
		}
	})
}
