package report

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"jenderalscan/internal/models"
)

// ExportPDF generates a multi-page PDF 1.4 security audit report in pure Go without external runtime dependencies.
func ExportPDF(scan *models.ScanResult, lang string) ([]byte, error) {
	isEN := strings.EqualFold(lang, "en")
	doc := newPDFBuilder()

	// Header banner on Page 1
	doc.drawHeaderBanner(scan, isEN)
	doc.drawSeverityBoxes(scan.Summary)
	doc.drawMetadataSection(scan, isEN)

	if len(scan.Technologies) > 0 {
		doc.drawSectionTitle(pickStr(isEN, "Komponen Teknologi Terdeteksi", "Detected Technology Stack"))
		for _, t := range scan.Technologies {
			ver := t.Version
			if ver == "" {
				ver = "-"
			}
			doc.writeWrappedLine(fmt.Sprintf("• [%s] %s (v: %s) — %s", t.Category, t.Name, ver, t.Source), 9, false, 0.15, 0.20, 0.28)
		}
		doc.moveDown(8)
	}

	doc.drawSectionTitle(fmt.Sprintf("%s (%d)", pickStr(isEN, "Daftar Detail Temuan Keamanan", "Detailed Security Findings"), len(scan.Findings)))

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

		doc.ensureSpace(120)
		r, g, b := sevRGB(f.Severity)
		doc.writeWrappedLine(fmt.Sprintf("%d. [%s] %s (%s)", idx+1, strings.ToUpper(string(f.Severity)), title, f.Module), 10.5, true, r, g, b)

		metaLine := fmt.Sprintf("Rule: %s | Confidence: %s", f.RuleID, f.Confidence)
		if f.CWE != "" {
			metaLine += " | " + f.CWE
		}
		if f.OWASP != "" {
			metaLine += " | " + f.OWASP
		}
		doc.writeWrappedLine(metaLine, 8.5, false, 0.35, 0.40, 0.48)

		doc.writeWrappedLine(pickStr(isEN, "Apa Ini: ", "Description: ")+desc, 9, false, 0.1, 0.12, 0.16)
		doc.writeWrappedLine(pickStr(isEN, "Dampak: ", "Impact: ")+impact, 9, false, 0.1, 0.12, 0.16)
		doc.writeWrappedLine(pickStr(isEN, "Rekomendasi: ", "Recommendation: ")+rec, 9, false, 0.05, 0.30, 0.20)

		if f.Evidence != "" {
			evClean := strings.ReplaceAll(f.Evidence, "\r\n", "\n")
			for _, evLine := range strings.Split(evClean, "\n") {
				if strings.TrimSpace(evLine) == "" {
					continue
				}
				doc.writeWrappedLine("   Evidence: "+evLine, 8, false, 0.28, 0.32, 0.38)
			}
		}
		doc.moveDown(10)
	}

	return doc.Bytes(), nil
}

func pickStr(isEN bool, idStr, enStr string) string {
	if isEN {
		return enStr
	}
	return idStr
}

func sevRGB(s models.Severity) (float64, float64, float64) {
	switch s {
	case models.SeverityHigh:
		return 0.82, 0.12, 0.12
	case models.SeverityMedium:
		return 0.85, 0.38, 0.04
	case models.SeverityLow:
		return 0.68, 0.48, 0.02
	default:
		return 0.25, 0.32, 0.42
	}
}

type pdfBuilder struct {
	pages   []*bytes.Buffer
	curr    *bytes.Buffer
	cursorY float64
}

const (
	pdfPageW   = 595.28 // A4 width pt
	pdfPageH   = 841.89 // A4 height pt
	pdfMarginX = 42.0
	pdfBottomY = 48.0
)

func newPDFBuilder() *pdfBuilder {
	b := &pdfBuilder{}
	b.newPage()
	return b
}

func (b *pdfBuilder) newPage() {
	buf := &bytes.Buffer{}
	b.pages = append(b.pages, buf)
	b.curr = buf
	b.cursorY = pdfPageH - 42.0
}

func (b *pdfBuilder) ensureSpace(needed float64) {
	if b.cursorY-needed < pdfBottomY {
		b.newPage()
	}
}

func (b *pdfBuilder) moveDown(pt float64) {
	b.cursorY -= pt
	if b.cursorY < pdfBottomY {
		b.newPage()
	}
}

func (b *pdfBuilder) drawHeaderBanner(scan *models.ScanResult, isEN bool) {
	// Dark slate rectangle
	bannerH := 58.0
	topY := b.cursorY - bannerH
	fmt.Fprintf(b.curr, "0.06 0.09 0.16 rg %.2f %.2f %.2f %.2f re f\n", pdfMarginX, topY, pdfPageW-2*pdfMarginX, bannerH)

	title := pickStr(isEN, "JENDERALSCAN — LAPORAN AUDIT KEAMANAN WEB", "JENDERALSCAN — WEB SECURITY AUDIT REPORT")
	sub := fmt.Sprintf("Target: %s | Host: %s | Generated: %s", scan.TargetURL, scan.NormalizedHost, time.Now().Format("2006-01-02 15:04"))

	b.drawTextAt(pdfMarginX+14, topY+34, title, 13, true, 1, 1, 1)
	b.drawTextAt(pdfMarginX+14, topY+16, sub, 9, false, 0.75, 0.82, 0.90)
	b.cursorY = topY - 16
}

func (b *pdfBuilder) drawSeverityBoxes(sum models.SeveritySummary) {
	boxW := (pdfPageW - 2*pdfMarginX - 36) / 4.0
	boxH := 42.0
	topY := b.cursorY - boxH

	items := []struct {
		label   string
		count   int
		r, g, b float64
	}{
		{"HIGH", sum.High, 0.85, 0.15, 0.15},
		{"MEDIUM", sum.Medium, 0.90, 0.42, 0.06},
		{"LOW", sum.Low, 0.78, 0.56, 0.04},
		{"INFO", sum.Info, 0.30, 0.38, 0.48},
	}

	for i, it := range items {
		x := pdfMarginX + float64(i)*(boxW+12)
		fmt.Fprintf(b.curr, "%.2f %.2f %.2f rg %.2f %.2f %.2f %.2f re f\n", it.r, it.g, it.b, x, topY, boxW, boxH)
		b.drawTextAt(x+12, topY+24, fmt.Sprintf("%d", it.count), 14, true, 1, 1, 1)
		b.drawTextAt(x+12, topY+10, it.label, 8.5, true, 0.95, 0.95, 0.95)
	}
	b.cursorY = topY - 18
}

func (b *pdfBuilder) drawMetadataSection(scan *models.ScanResult, isEN bool) {
	b.drawSectionTitle(pickStr(isEN, "Ringkasan Eksekusi & Otorisasi", "Execution & Authorization Summary"))
	authNote := scan.AuthorizationNote
	if authNote == "" {
		authNote = pickStr(isEN, "Dikonfirmasi Pemilik / Izin Resmi", "Confirmed Owner / Written Authorization")
	}
	b.writeWrappedLine(fmt.Sprintf("Scan ID: %s | Profile: %s | Status: %s", scan.ID, scan.Profile, scan.Status), 9, false, 0.15, 0.2, 0.25)
	b.writeWrappedLine(fmt.Sprintf("Duration: %.2fs | Requests Sent: %d | Scope Lock: Active (%s)", float64(scan.DurationMs)/1000.0, scan.RequestsSent, scan.NormalizedHost), 9, false, 0.15, 0.2, 0.25)
	b.writeWrappedLine(fmt.Sprintf("Legal Authorization: %s", authNote), 9, false, 0.15, 0.2, 0.25)
	b.moveDown(8)
}

func (b *pdfBuilder) drawSectionTitle(title string) {
	b.ensureSpace(32)
	b.drawTextAt(pdfMarginX, b.cursorY, title, 11.5, true, 0.06, 0.15, 0.28)
	lineY := b.cursorY - 5
	fmt.Fprintf(b.curr, "0.80 0.84 0.90 RG 0.8 w %.2f %.2f m %.2f %.2f l S\n", pdfMarginX, lineY, pdfPageW-pdfMarginX, lineY)
	b.cursorY -= 18
}

func (b *pdfBuilder) writeWrappedLine(text string, fontSize float64, bold bool, r, g, bl float64) {
	maxChars := int((pdfPageW - 2*pdfMarginX) / (fontSize * 0.50))
	if maxChars < 40 {
		maxChars = 40
	}
	lines := wrapText(sanitizePDFASCII(text), maxChars)
	lineH := fontSize + 4.5
	for _, ln := range lines {
		b.ensureSpace(lineH + 4)
		b.drawTextAt(pdfMarginX, b.cursorY, ln, fontSize, bold, r, g, bl)
		b.cursorY -= lineH
	}
}

func (b *pdfBuilder) drawTextAt(x, y float64, text string, size float64, bold bool, r, g, bl float64) {
	fontRef := "/F1"
	if bold {
		fontRef = "/F2"
	}
	safe := escapePDFString(sanitizePDFASCII(text))
	fmt.Fprintf(b.curr, "BT %s %.1f Tf %.2f %.2f %.2f rg %.2f %.2f Td (%s) Tj ET\n", fontRef, size, r, g, bl, x, y, safe)
}

func (b *pdfBuilder) Bytes() []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")

	// Object layout:
	// 1: Catalog
	// 2: Pages
	// 3: Font F1 (Helvetica)
	// 4: Font F2 (Helvetica-Bold)
	// For each page i (0..N-1):
	//   obj (5 + 2*i): Page
	//   obj (6 + 2*i): Content stream

	numPages := len(b.pages)
	totalObjs := 4 + 2*numPages
	offsets := make([]int, totalObjs+1)

	writeObj := func(id int, body string) {
		offsets[id] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", id, body)
	}

	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")

	var kids []string
	for i := 0; i < numPages; i++ {
		kids = append(kids, fmt.Sprintf("%d 0 R", 5+2*i))
	}
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), numPages))
	writeObj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	writeObj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

	for i, pageBuf := range b.pages {
		pageObjID := 5 + 2*i
		streamObjID := 6 + 2*i
		streamBytes := pageBuf.Bytes()

		pageDict := fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>",
			pdfPageW, pdfPageH, streamObjID,
		)
		writeObj(pageObjID, pageDict)

		streamBody := fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(streamBytes), string(streamBytes))
		writeObj(streamObjID, streamBody)
	}

	xrefPos := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", totalObjs+1)
	for id := 1; id <= totalObjs; id++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[id])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", totalObjs+1, xrefPos)
	return out.Bytes()
}

func sanitizePDFASCII(s string) string {
	replacer := strings.NewReplacer(
		"—", "-",
		"–", "-",
		"•", "*",
		"→", "->",
		"←", "<-",
		"“", "\"",
		"”", "\"",
		"’", "'",
		"‘", "'",
		"·", "|",
	)
	s = replacer.Replace(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		} else {
			b.WriteRune(' ')
		}
	}
	return b.String()
}

func escapePDFString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `(`, `\(`)
	s = strings.ReplaceAll(s, `)`, `\)`)
	return s
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	curr := words[0]
	for _, w := range words[1:] {
		if len(curr)+1+len(w) > width {
			lines = append(lines, curr)
			curr = w
		} else {
			curr += " " + w
		}
	}
	lines = append(lines, curr)
	return lines
}
