package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"jenderalscan/internal/models"
)

// ExportJSON serializes a ScanResult as indented machine-readable JSON.
func ExportJSON(scan *models.ScanResult) ([]byte, error) {
	return json.MarshalIndent(scan, "", "  ")
}

// ExportMarkdown renders a structured GitHub-Flavored Markdown (.md) security audit report.
func ExportMarkdown(scan *models.ScanResult, lang string) ([]byte, error) {
	isEN := strings.EqualFold(lang, "en")
	var b strings.Builder

	pick := func(idStr, enStr string) string {
		if isEN {
			return enStr
		}
		return idStr
	}

	generatedAt := time.Now().Format("2006-01-02 15:04:05 MST")
	durationSec := fmt.Sprintf("%.2fs", float64(scan.DurationMs)/1000.0)
	authNote := scan.AuthorizationNote
	if authNote == "" {
		authNote = pick("Dikonfirmasi Pemilik / Izin Tertulis Resmi", "Confirmed Owner / Written Authorization")
	}

	b.WriteString(fmt.Sprintf("# JenderalScan — %s\n\n", pick("Laporan Audit Permukaan Keamanan Web", "Web Security Surface Audit Report")))
	b.WriteString(fmt.Sprintf("> **Target:** `%s` · **Host:** `%s` · **%s:** %s\n\n",
		scan.TargetURL, scan.NormalizedHost, pick("Dibuat pada", "Generated at"), generatedAt))

	// 1. Metadata Table
	b.WriteString(fmt.Sprintf("## 1. %s\n\n", pick("Metadata & Ruang Lingkup Scan", "Scan Metadata & Scope")))
	b.WriteString(fmt.Sprintf("| %s | %s |\n", pick("Parameter", "Property"), pick("Nilai", "Value")))
	b.WriteString("| :--- | :--- |\n")
	b.WriteString(fmt.Sprintf("| **Scan ID** | `%s` |\n", scan.ID))
	b.WriteString(fmt.Sprintf("| **Target URL** | `%s` |\n", scan.TargetURL))
	b.WriteString(fmt.Sprintf("| **Host (Scope Locked)** | `%s` |\n", scan.NormalizedHost))
	b.WriteString(fmt.Sprintf("| **%s** | `%s` |\n", pick("Profil Scan", "Scan Profile"), scan.Profile))
	b.WriteString(fmt.Sprintf("| **Status** | `%s` |\n", strings.ToUpper(scan.Status)))
	b.WriteString(fmt.Sprintf("| **%s** | %s (%d requests) |\n", pick("Durasi & Request", "Duration & Requests"), durationSec, scan.RequestsSent))
	b.WriteString(fmt.Sprintf("| **%s** | %s |\n", pick("Waktu Mulai", "Started At"), scan.StartedAt.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("| **%s** | %s |\n\n", pick("Otorisasi Legal", "Legal Authorization"), authNote))

	// 2. Severity Summary Table
	b.WriteString(fmt.Sprintf("## 2. %s\n\n", pick("Ringkasan Eksekutif Severity", "Executive Severity Summary")))
	b.WriteString("| High | Medium | Low | Info | Total |\n")
	b.WriteString("| :---: | :---: | :---: | :---: | :---: |\n")
	b.WriteString(fmt.Sprintf("| **%d** | **%d** | **%d** | **%d** | **%d** |\n\n",
		scan.Summary.High, scan.Summary.Medium, scan.Summary.Low, scan.Summary.Info, scan.Summary.Total))

	// Diff section if available
	if scan.Diff != nil && scan.Diff.PreviousScanID != "" {
		b.WriteString(fmt.Sprintf("### %s (%s)\n\n",
			pick("Perbandingan dengan Scan Sebelumnya", "Comparison Against Previous Scan"),
			scan.Diff.PreviousDate.Format("2006-01-02 15:04")))
		b.WriteString(fmt.Sprintf("- **%s:** +%d\n", pick("Temuan Baru (New)", "New Findings"), scan.Diff.NewCount))
		b.WriteString(fmt.Sprintf("- **%s:** %d\n", pick("Temuan Tetap (Recurring)", "Recurring Findings"), scan.Diff.RecurringCount))
		b.WriteString(fmt.Sprintf("- **%s:** -%d\n\n", pick("Temuan Teratasi (Fixed)", "Fixed / Resolved Findings"), scan.Diff.FixedCount))
	}

	// 3. Detected Tech Stack
	if len(scan.Technologies) > 0 {
		b.WriteString(fmt.Sprintf("## 3. %s\n\n", pick("Komponen Teknologi Terdeteksi", "Detected Technology Stack")))
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			pick("Komponen", "Component"),
			pick("Bahasa / Ekosistem", "Language / Ecosystem"),
			pick("Kategori", "Category"),
			pick("Versi", "Version"),
			pick("Kaitan / Estimasi CVE", "Associated / Potential CVEs"),
			pick("Sumber Deteksi", "Detection Source")))
		b.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
		for _, t := range scan.Technologies {
			ver := t.Version
			if ver == "" {
				ver = pick("Disembunyikan", "Hidden")
			}
			langStr := t.Language
			if langStr == "" {
				langStr = "-"
			}
			cveStr := "-"
			if len(t.PotentialCVEs) > 0 {
				cveStr = strings.Join(t.PotentialCVEs, ", ")
			}
			b.WriteString(fmt.Sprintf("| **%s** | %s | %s | `%s` | %s | %s |\n",
				escapeMDCell(t.Name), escapeMDCell(langStr), escapeMDCell(t.Category), escapeMDCell(ver), escapeMDCell(cveStr), escapeMDCell(t.Source)))
		}
		b.WriteString("\n")
	}

	// 4. Module Execution Summary
	if len(scan.ModuleStatuses) > 0 {
		b.WriteString(fmt.Sprintf("## 4. %s\n\n", pick("Status Eksekusi Modul", "Module Execution Status")))
		b.WriteString(fmt.Sprintf("| %s | Status | %s | %s |\n",
			pick("Modul", "Module"),
			pick("Temuan", "Findings"),
			pick("Durasi", "Duration")))
		b.WriteString("| :--- | :---: | :---: | :---: |\n")
		for _, ms := range scan.ModuleStatuses {
			b.WriteString(fmt.Sprintf("| `%s` (%s) | `%s` | %d | %d ms |\n",
				ms.Module, escapeMDCell(ms.Name), ms.Status, ms.Findings, ms.DurationMs))
		}
		b.WriteString("\n")
	}

	// 5. Detailed Findings
	b.WriteString(fmt.Sprintf("## 5. %s (%d)\n\n",
		pick("Daftar Detail Temuan Keamanan", "Detailed Security Findings"),
		len(scan.Findings)))

	if len(scan.Findings) == 0 {
		b.WriteString(fmt.Sprintf("_%s_\n\n", pick("Tidak ada temuan yang terdeteksi pada scan ini.", "No findings were detected during this scan.")))
	}

	for idx, f := range scan.Findings {
		title := f.Title
		desc := f.Description
		impact := f.Impact
		rec := f.Recommendation
		if isEN {
			if f.TitleEN != "" {
				title = f.TitleEN
			}
			if f.DescriptionEN != "" {
				desc = f.DescriptionEN
			}
			if f.ImpactEN != "" {
				impact = f.ImpactEN
			}
			if f.RecommendationEN != "" {
				rec = f.RecommendationEN
			}
		}

		b.WriteString(fmt.Sprintf("### 5.%d. [%s] %s\n\n", idx+1, strings.ToUpper(string(f.Severity)), title))

		var metaBadges []string
		metaBadges = append(metaBadges, fmt.Sprintf("**Module:** `%s`", f.Module))
		metaBadges = append(metaBadges, fmt.Sprintf("**Rule:** `%s`", f.RuleID))
		metaBadges = append(metaBadges, fmt.Sprintf("**Confidence:** `%s`", f.Confidence))
		if f.CWE != "" {
			metaBadges = append(metaBadges, fmt.Sprintf("**CWE:** `%s`", f.CWE))
		}
		if f.OWASP != "" {
			metaBadges = append(metaBadges, fmt.Sprintf("**OWASP:** `%s`", f.OWASP))
		}
		if f.CVSS > 0 {
			metaBadges = append(metaBadges, fmt.Sprintf("**CVSS:** `%.1f`", f.CVSS))
		}
		if f.DiffStatus != "" {
			metaBadges = append(metaBadges, fmt.Sprintf("**Status:** `%s`", f.DiffStatus))
		}
		b.WriteString(strings.Join(metaBadges, " · ") + "\n\n")

		b.WriteString(fmt.Sprintf("- **%s:** %s\n", pick("Apa Ini (Deskripsi)", "What This Is (Description)"), desc))
		b.WriteString(fmt.Sprintf("- **%s:** %s\n", pick("Kenapa Berisiko (Dampak)", "Why It Is Risky (Impact)"), impact))
		b.WriteString(fmt.Sprintf("- **%s:** %s\n\n", pick("Cara Perbaiki (Rekomendasi)", "How To Fix (Recommendation)"), rec))

		if strings.TrimSpace(f.Evidence) != "" {
			b.WriteString(fmt.Sprintf("**%s:**\n```text\n%s\n```\n\n",
				pick("Bukti Teknis (Evidence)", "Technical Evidence"),
				strings.TrimSpace(f.Evidence)))
		}

		if len(f.References) > 0 {
			b.WriteString(fmt.Sprintf("**%s:**\n", pick("Referensi", "References")))
			for _, ref := range f.References {
				b.WriteString(fmt.Sprintf("- <%s>\n", ref))
			}
			b.WriteString("\n")
		}

		b.WriteString("---\n\n")
	}

	b.WriteString("_Generated by JenderalScan v1.0 · Non-Intrusive Desktop Web Vulnerability Surface Scanner_\n")
	return []byte(b.String()), nil
}

func escapeMDCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

type htmlReportData struct {
	Scan          *models.ScanResult
	GeneratedAt   string
	StartedAt     string
	CompletedAt   string
	DurationSec   string
	Lang          string
	IsEN          bool
}

// ExportHTML renders a standalone, executive & technical HTML security report.
func ExportHTML(scan *models.ScanResult, lang string) ([]byte, error) {
	isEN := strings.EqualFold(lang, "en")
	data := htmlReportData{
		Scan:        scan,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
		StartedAt:   scan.StartedAt.Format("2006-01-02 15:04:05"),
		CompletedAt: scan.CompletedAt.Format("2006-01-02 15:04:05"),
		DurationSec: fmt.Sprintf("%.2fs", float64(scan.DurationMs)/1000.0),
		Lang:        lang,
		IsEN:        isEN,
	}

	funcMap := template.FuncMap{
		"sevClass": func(s models.Severity) string {
			switch s {
			case models.SeverityHigh:
				return "sev-high"
			case models.SeverityMedium:
				return "sev-medium"
			case models.SeverityLow:
				return "sev-low"
			default:
				return "sev-info"
			}
		},
		"pickTitle": func(f models.Finding) string {
			if isEN && f.TitleEN != "" {
				return f.TitleEN
			}
			return f.Title
		},
		"pickDesc": func(f models.Finding) string {
			if isEN && f.DescriptionEN != "" {
				return f.DescriptionEN
			}
			return f.Description
		},
		"pickImpact": func(f models.Finding) string {
			if isEN && f.ImpactEN != "" {
				return f.ImpactEN
			}
			return f.Impact
		},
		"pickRec": func(f models.Finding) string {
			if isEN && f.RecommendationEN != "" {
				return f.RecommendationEN
			}
			return f.Recommendation
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportHTMLTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const reportHTMLTemplate = `<!DOCTYPE html>
<html lang="{{if .IsEN}}en{{else}}id{{end}}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JenderalScan Report — {{.Scan.TargetURL}}</title>
<style>
  :root {
    --bg: #f8fafc;
    --card: #ffffff;
    --text: #0f172a;
    --muted: #475569;
    --border: #e2e8f0;
    --high: #dc2626;
    --high-bg: #fef2f2;
    --medium: #ea580c;
    --medium-bg: #fff7ed;
    --low: #ca8a04;
    --low-bg: #fefce8;
    --info: #475569;
    --info-bg: #f1f5f9;
    --accent: #0284c7;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 32px 20px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.55;
  }
  .container { max-width: 1020px; margin: 0 auto; }
  .header {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #fff;
    padding: 28px 32px;
    border-radius: 12px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }
  .header h1 { margin: 0 0 6px 0; font-size: 24px; letter-spacing: -0.02em; }
  .header p { margin: 0; color: #94a3b8; font-size: 14px; }
  .badge-auth {
    display: inline-block;
    background: rgba(16, 185, 129, 0.2);
    color: #34d399;
    border: 1px solid rgba(52, 211, 153, 0.4);
    font-size: 12px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 999px;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 20px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.03);
  }
  .card h2 {
    margin: 0 0 16px 0;
    font-size: 17px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
  }
  .meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px;
    font-size: 14px;
  }
  .meta-item span { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
  .meta-item strong { font-size: 14px; word-break: break-all; }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
  }
  .sum-box {
    padding: 16px;
    border-radius: 8px;
    text-align: center;
    border: 1px solid var(--border);
  }
  .sum-box .num { font-size: 28px; font-weight: 700; display: block; }
  .sum-box .lbl { font-size: 12px; font-weight: 600; text-transform: uppercase; }
  .sum-high { background: var(--high-bg); color: var(--high); border-color: #fecaca; }
  .sum-medium { background: var(--medium-bg); color: var(--medium); border-color: #fed7aa; }
  .sum-low { background: var(--low-bg); color: var(--low); border-color: #fef08a; }
  .sum-info { background: var(--info-bg); color: var(--info); border-color: #cbd5e1; }
  .finding {
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 16px;
    overflow: hidden;
    background: #fff;
    page-break-inside: avoid;
  }
  .finding-head {
    padding: 12px 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    background: #f8fafc;
  }
  .finding-title { font-weight: 600; font-size: 15px; }
  .sev-pill {
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
  }
  .sev-high { background: var(--high-bg); color: var(--high); border: 1px solid #fecaca; }
  .sev-medium { background: var(--medium-bg); color: var(--medium); border: 1px solid #fed7aa; }
  .sev-low { background: var(--low-bg); color: var(--low); border: 1px solid #fef08a; }
  .sev-info { background: var(--info-bg); color: var(--info); border: 1px solid #cbd5e1; }
  .finding-body { padding: 16px 18px; font-size: 14px; }
  .section-label {
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    color: var(--muted);
    margin: 12px 0 4px 0;
  }
  .section-label:first-child { margin-top: 0; }
  pre.evidence {
    background: #0f172a;
    color: #e2e8f0;
    padding: 12px 14px;
    border-radius: 6px;
    font-size: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
    margin: 6px 0;
  }
  .tags { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; font-size: 12px; }
  .tag { background: #f1f5f9; color: #334155; padding: 2px 8px; border-radius: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; background: #f8fafc; }
  .footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 28px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>JenderalScan — {{if .IsEN}}Web Security Surface Audit Report{{else}}Laporan Audit Permukaan Keamanan Web{{end}}</h1>
      <p>{{.Scan.TargetURL}} · {{if .IsEN}}Generated{{else}}Dibuat pada{{end}} {{.GeneratedAt}}</p>
    </div>
    <div>
      <span class="badge-auth">{{if .IsEN}}Authorized Non-Intrusive Scan{{else}}Scan Non-Intrusif Terotorisasi{{end}}</span>
    </div>
  </div>

  <div class="card">
    <h2>{{if .IsEN}}Scan Metadata & Scope{{else}}Metadata & Ruang Lingkup Scan{{end}}</h2>
    <div class="meta-grid">
      <div class="meta-item"><span>Target URL</span><strong>{{.Scan.TargetURL}}</strong></div>
      <div class="meta-item"><span>Host (Scope Locked)</span><strong>{{.Scan.NormalizedHost}}</strong></div>
      <div class="meta-item"><span>{{if .IsEN}}Profile{{else}}Profil Scan{{end}}</span><strong>{{.Scan.Profile}}</strong></div>
      <div class="meta-item"><span>{{if .IsEN}}Duration & Requests{{else}}Durasi & Request{{end}}</span><strong>{{.DurationSec}} ({{.Scan.RequestsSent}} req)</strong></div>
      <div class="meta-item"><span>{{if .IsEN}}Started At{{else}}Waktu Mulai{{end}}</span><strong>{{.StartedAt}}</strong></div>
      <div class="meta-item"><span>{{if .IsEN}}Authorization Note{{else}}Catatan Izin{{end}}</span><strong>{{if .Scan.AuthorizationNote}}{{.Scan.AuthorizationNote}}{{else}}Confirmed Owner / Authorized{{end}}</strong></div>
    </div>
  </div>

  <div class="card">
    <h2>{{if .IsEN}}Executive Severity Summary{{else}}Ringkasan Eksekutif Severity{{end}}</h2>
    <div class="summary-grid">
      <div class="sum-box sum-high"><span class="num">{{.Scan.Summary.High}}</span><span class="lbl">High</span></div>
      <div class="sum-box sum-medium"><span class="num">{{.Scan.Summary.Medium}}</span><span class="lbl">Medium</span></div>
      <div class="sum-box sum-low"><span class="num">{{.Scan.Summary.Low}}</span><span class="lbl">Low</span></div>
      <div class="sum-box sum-info"><span class="num">{{.Scan.Summary.Info}}</span><span class="lbl">Info</span></div>
      <div class="sum-box"><span class="num">{{.Scan.Summary.Total}}</span><span class="lbl">Total</span></div>
    </div>
  </div>

  {{if .Scan.Technologies}}
  <div class="card">
    <h2>{{if .IsEN}}Detected Technology Stack{{else}}Komponen Teknologi Terdeteksi{{end}}</h2>
    <table>
      <thead>
        <tr>
          <th>{{if .IsEN}}Component{{else}}Komponen{{end}}</th>
          <th>{{if .IsEN}}Category{{else}}Kategori{{end}}</th>
          <th>{{if .IsEN}}Version{{else}}Versi{{end}}</th>
          <th>{{if .IsEN}}Detection Source{{else}}Sumber Deteksi{{end}}</th>
        </tr>
      </thead>
      <tbody>
        {{range .Scan.Technologies}}
        <tr>
          <td><strong>{{.Name}}</strong></td>
          <td>{{.Category}}</td>
          <td>{{if .Version}}{{.Version}}{{else}}-{{end}}</td>
          <td>{{.Source}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <div class="card">
    <h2>{{if .IsEN}}Detailed Security Findings{{else}}Daftar Detail Temuan Keamanan{{end}} ({{len .Scan.Findings}})</h2>
    {{range .Scan.Findings}}
    <div class="finding">
      <div class="finding-head">
        <div class="finding-title">{{pickTitle .}}</div>
        <span class="sev-pill {{sevClass .Severity}}">{{.Severity}}</span>
      </div>
      <div class="finding-body">
        <div class="section-label">{{if $.IsEN}}What This Is (Description){{else}}Apa Ini (Deskripsi){{end}}</div>
        <div>{{pickDesc .}}</div>

        <div class="section-label">{{if $.IsEN}}Why It Is Risky (Impact){{else}}Kenapa Berisiko (Dampak){{end}}</div>
        <div>{{pickImpact .}}</div>

        <div class="section-label">{{if $.IsEN}}How To Fix (Recommendation){{else}}Cara Perbaiki (Rekomendasi){{end}}</div>
        <div>{{pickRec .}}</div>

        {{if .Evidence}}
        <div class="section-label">{{if $.IsEN}}Technical Evidence{{else}}Bukti Teknis{{end}}</div>
        <pre class="evidence">{{.Evidence}}</pre>
        {{end}}

        <div class="tags">
          <span class="tag">Module: {{.Module}}</span>
          <span class="tag">Rule: {{.RuleID}}</span>
          <span class="tag">Confidence: {{.Confidence}}</span>
          {{if .CWE}}<span class="tag">{{.CWE}}</span>{{end}}
          {{if .OWASP}}<span class="tag">{{.OWASP}}</span>{{end}}
          {{if .DiffStatus}}<span class="tag">Status: {{.DiffStatus}}</span>{{end}}
        </div>
      </div>
    </div>
    {{end}}
  </div>

  <div class="footer">
    JenderalScan v1.0 · Non-Intrusive Desktop Web Vulnerability Scanner · Legal & Authorized Security Surface Audit
  </div>
</div>
</body>
</html>`
