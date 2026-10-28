package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
)

// DNSModule performs DNS record inspection, SPF/DMARC policy checks, and passive subdomain enumeration.
type DNSModule struct{}

func NewDNSModule() *DNSModule {
	return &DNSModule{}
}

func (m *DNSModule) ID() models.ModuleID {
	return models.ModuleDNS
}

func (m *DNSModule) Name() string {
	return "DNS & Subdomain Pasif"
}

func (m *DNSModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
	host := scanCtx.Target.Hostname
	targetURL := scanCtx.Target.NormalizedURL

	// Skip DNS checks if target is a raw IP address or localhost
	if net.ParseIP(host) != nil || host == "localhost" {
		return []models.Finding{
			engine.NewFinding(
				models.ModuleDNS,
				"DNS-LOCAL-SKIP",
				host,
				"dns-local-skip",
				models.SeverityInfo,
				models.ConfidenceHigh,
				"Target Berupa Alamat IP / Localhost (Enumerasi DNS Dilewati)",
				"Target is an IP Address / Localhost (DNS Enumeration Skipped)",
				fmt.Sprintf("Target `%s` merupakan alamat IP langsung atau localhost sehingga pemeriksaan record domain publik (MX/SPF/DMARC/Subdomain) tidak relevan.", host),
				fmt.Sprintf("Target `%s` is a direct IP address or localhost; public domain record checks (MX/SPF/DMARC/Subdomains) were skipped.", host),
				"Tidak ada risiko langsung; gunakan nama domain penuh (FQDN) untuk memeriksa postur DNS.",
				"No direct risk; scan a fully qualified domain name (FQDN) to evaluate DNS security records.",
				"Gunakan nama domain penuh (FQDN) apabila ingin memeriksa konfigurasi SPF, DMARC, dan subdomain pasif.",
				"Provide a fully qualified domain name (FQDN) to inspect SPF, DMARC, and passive subdomains.",
				fmt.Sprintf("Host: %s", host),
				targetURL,
				"CWE-200",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{"https://datatracker.ietf.org/doc/html/rfc7208"},
			),
		}, nil
	}

	resolver := net.DefaultResolver
	var findings []models.Finding
	var recordLines []string

	// 1. Lookup A / AAAA
	if err := scanCtx.Client.WaitRateLimit(ctx); err != nil {
		return nil, err
	}
	ips, _ := resolver.LookupIPAddr(ctx, host)
	if len(ips) > 0 {
		var ipStrs []string
		for _, ip := range ips {
			ipStrs = append(ipStrs, ip.String())
		}
		recordLines = append(recordLines, fmt.Sprintf("A/AAAA: %s", strings.Join(ipStrs, ", ")))
	}

	// 2. Lookup CNAME
	if cname, err := resolver.LookupCNAME(ctx, host); err == nil && cname != "" && strings.TrimSuffix(cname, ".") != host {
		recordLines = append(recordLines, fmt.Sprintf("CNAME: %s", cname))
	}

	// 3. Lookup NS
	if nss, err := resolver.LookupNS(ctx, host); err == nil && len(nss) > 0 {
		var nsList []string
		for _, ns := range nss {
			nsList = append(nsList, ns.Host)
		}
		recordLines = append(recordLines, fmt.Sprintf("NS: %s", strings.Join(nsList, ", ")))
	}

	// 4. Lookup MX
	mxs, _ := resolver.LookupMX(ctx, host)
	if len(mxs) > 0 {
		var mxList []string
		for _, mx := range mxs {
			mxList = append(mxList, fmt.Sprintf("%s (pref %d)", mx.Host, mx.Pref))
		}
		recordLines = append(recordLines, fmt.Sprintf("MX: %s", strings.Join(mxList, ", ")))
	}

	// 5. Lookup TXT & Check SPF
	txts, _ := resolver.LookupTXT(ctx, host)
	var spfRecord string
	for _, txt := range txts {
		recordLines = append(recordLines, fmt.Sprintf("TXT: %s", txt))
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
			spfRecord = strings.TrimSpace(txt)
		}
	}

	if spfRecord == "" {
		findings = append(findings, engine.NewFinding(
			models.ModuleDNS,
			"DNS-SPF-MISSING",
			host,
			"spf-missing",
			models.SeverityLow,
			models.ConfidenceHigh,
			"Record DNS SPF (Sender Policy Framework) Tidak Ditemukan",
			"Missing DNS SPF (Sender Policy Framework) Record",
			fmt.Sprintf("Domain `%s` tidak memiliki record TXT `v=spf1`.", host),
			fmt.Sprintf("The domain `%s` does not publish a `v=spf1` TXT record.", host),
			"Tanpa kebijakan SPF, pihak tidak berwenang lebih mudah memalsukan (spoofing) pengirim email menggunakan nama domain ini.",
			"Without an SPF policy, attackers can more easily spoof emails appearing to originate from this domain.",
			"Tambahkan record TXT SPF pada DNS (misalnya `v=spf1 -all` jika domain tidak mengirim email, atau daftarkan server email resmi lalu akhiri dengan `~all` / `-all`).",
			"Publish a DNS TXT SPF record (e.g., `v=spf1 -all` if the domain sends no mail, or authorize legitimate mail servers ending with `~all` / `-all`).",
			fmt.Sprintf("Domain: %s\nTXT Records Checked: %d (no v=spf1 found)", host, len(txts)),
			targetURL,
			"CWE-290",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://datatracker.ietf.org/doc/html/rfc7208"},
		))
	} else if strings.Contains(strings.ToLower(spfRecord), "+all") {
		findings = append(findings, engine.NewFinding(
			models.ModuleDNS,
			"DNS-SPF-PERMISSIVE",
			host,
			"spf-plus-all",
			models.SeverityMedium,
			models.ConfidenceHigh,
			"Kebijakan SPF Terlalu Permisif (+all)",
			"Overly Permissive SPF Policy (+all)",
			fmt.Sprintf("Record SPF mengandung mekanisme `+all` (`%s`) yang mengizinkan semua server di internet mengirim email atas nama domain ini.", spfRecord),
			fmt.Sprintf("The SPF record contains `+all` (`%s`), which authorizes any host on the internet to send mail on behalf of this domain.", spfRecord),
			"Memungkinkan email spoofing dan phishing atas nama organisasi tanpa penolakan dari penerima.",
			"Enables unrestricted email spoofing and phishing impersonating the domain.",
			"Ganti `+all` dengan `~all` (SoftFail) atau `-all` (HardFail).",
			"Replace `+all` with `~all` (SoftFail) or `-all` (HardFail).",
			fmt.Sprintf("SPF Record: %s", spfRecord),
			targetURL,
			"CWE-290",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://datatracker.ietf.org/doc/html/rfc7208"},
		))
	}

	// 6. Check DMARC (_dmarc.<host>)
	if err := scanCtx.Client.WaitRateLimit(ctx); err == nil {
		dmarcHost := "_dmarc." + host
		dmarcTXTs, _ := resolver.LookupTXT(ctx, dmarcHost)
		var dmarcRecord string
		for _, dt := range dmarcTXTs {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(dt)), "v=dmarc1") {
				dmarcRecord = strings.TrimSpace(dt)
				recordLines = append(recordLines, fmt.Sprintf("DMARC: %s", dmarcRecord))
				break
			}
		}
		if dmarcRecord == "" {
			findings = append(findings, engine.NewFinding(
				models.ModuleDNS,
				"DNS-DMARC-MISSING",
				host,
				"dmarc-missing",
				models.SeverityLow,
				models.ConfidenceHigh,
				"Record DNS DMARC (_dmarc) Tidak Ditemukan",
				"Missing DNS DMARC (_dmarc) Record",
				fmt.Sprintf("Record TXT pada `%s` tidak ditemukan.", dmarcHost),
				fmt.Sprintf("No `v=DMARC1` TXT record was found at `%s`.", dmarcHost),
				"Tanpa DMARC, pemilik domain tidak memiliki instruksi kebijakan penolakan (`quarantine`/`reject`) maupun pelaporan atas kegagalan SPF/DKIM.",
				"Without DMARC, receiving mail servers lack policy enforcement instructions (`quarantine`/`reject`) when SPF/DKIM checks fail.",
				fmt.Sprintf("Tambahkan record TXT pada `%s`, misalnya `v=DMARC1; p=quarantine; rua=mailto:dmarc@%s`.", dmarcHost, host),
				fmt.Sprintf("Publish a TXT record at `%s`, e.g., `v=DMARC1; p=quarantine; rua=mailto:dmarc@%s`.", dmarcHost, host),
				fmt.Sprintf("Queried Host: %s → No v=DMARC1 TXT record", dmarcHost),
				targetURL,
				"CWE-290",
				"OWASP A05:2021 - Security Misconfiguration",
				[]string{"https://datatracker.ietf.org/doc/html/rfc7489"},
			))
		}
	}

	// 7. Passive Subdomain Enumeration via Certificate Transparency (crt.sh)
	var subdomains []string
	if ctx.Err() == nil {
		subdomains = queryPassiveCTSubdomains(ctx, host)
	}
	if len(subdomains) > 0 {
		recordLines = append(recordLines, fmt.Sprintf("Passive Subdomains (Certificate Transparency): %s", strings.Join(subdomains, ", ")))
	}

	if len(recordLines) > 0 {
		findings = append(findings, engine.NewFinding(
			models.ModuleDNS,
			"DNS-RECORDS-SUMMARY",
			host,
			"dns-summary",
			models.SeverityInfo,
			models.ConfidenceHigh,
			fmt.Sprintf("Inventaris DNS & Subdomain Pasif (%d Subdomain Ditemukan)", len(subdomains)),
			fmt.Sprintf("DNS Records & Passive Subdomain Inventory (%d Subdomains Found)", len(subdomains)),
			"Ringkasan record DNS publik serta daftar subdomain yang ditemukan secara pasif melalui log Certificate Transparency publik.",
			"Summary of public DNS records and subdomains discovered passively via public Certificate Transparency logs.",
			"Subdomain lama atau staging yang terlupakan (shadow IT) sering memiliki konfigurasi keamanan yang lebih lemah atau berisiko subdomain takeover.",
			"Forgotten staging or legacy subdomains (Shadow IT) frequently have weaker security controls or dangling CNAMEs susceptible to subdomain takeover.",
			"Tinjau inventaris subdomain secara berkala dan hapus record DNS yang mengarah ke layanan yang sudah tidak aktif (sesuai Scope Lock, subdomain tidak dipindai otomatis tanpa izin eksplisit).",
			"Review the subdomain inventory periodically and remove dangling DNS records pointing to decommissioned services (per Scope Lock, discovered subdomains are not scanned automatically).",
			strings.Join(recordLines, "\n"),
			targetURL,
			"CWE-200",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://crt.sh/"},
		))
	}

	return findings, nil
}

func queryPassiveCTSubdomains(ctx context.Context, domain string) []string {
	ctCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	urlStr := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "JenderalScan/1.0 (Passive CT Lookup)")

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	unique := make(map[string]bool)
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			sub := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "*.")))
			if sub != "" && sub != domain && strings.HasSuffix(sub, "."+domain) && !strings.ContainsAny(sub, " *") {
				unique[sub] = true
			}
		}
	}

	var out []string
	for k := range unique {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 25 {
		out = out[:25]
	}
	return out
}
