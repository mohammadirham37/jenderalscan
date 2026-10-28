package modules

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
)

// TLSModule inspects TLS protocol versions, cipher suites, and X.509 certificate chains.
type TLSModule struct{}

func NewTLSModule() *TLSModule {
	return &TLSModule{}
}

func (m *TLSModule) ID() models.ModuleID {
	return models.ModuleTLS
}

func (m *TLSModule) Name() string {
	return "Konfigurasi TLS/SSL"
}

func (m *TLSModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
	host := scanCtx.Target.Hostname
	targetURL := scanCtx.Target.NormalizedURL
	var findings []models.Finding

	// Check if target is plain HTTP and did not redirect to HTTPS
	isPlainHTTP := scanCtx.Target.Scheme == "http" &&
		(scanCtx.Baseline == nil || !strings.HasPrefix(scanCtx.Baseline.FinalURL, "https://"))

	tlsPort := scanCtx.Target.Port
	if scanCtx.Target.Scheme == "http" {
		if tlsPort == "80" {
			tlsPort = "443"
		}
	}
	addr := net.JoinHostPort(host, tlsPort)
	timeout := time.Duration(scanCtx.Settings.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	if err := scanCtx.Client.WaitRateLimit(ctx); err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // We perform explicit x509 verification below to distinguish failure modes
	})

	if err != nil {
		if isPlainHTTP {
			findings = append(findings, engine.NewFinding(
				models.ModuleTLS,
				"TLS-NO-HTTPS",
				host,
				"no-https",
				models.SeverityHigh,
				models.ConfidenceHigh,
				"Website Tidak Menggunakan Enkripsi HTTPS / TLS",
				"Website Does Not Use HTTPS / TLS Encryption",
				"Target diakses melalui protokol HTTP tanpa enkripsi dan tidak mengalihkan trafik ke HTTPS.",
				"The target is served over unencrypted HTTP and does not redirect traffic to HTTPS.",
				"Seluruh lalu lintas data (termasuk kredensial login, cookie sesi, dan formulir) dikirim dalam teks biasa (plaintext) sehingga dapat disadap atau dimodifikasi oleh pihak ketiga di jaringan.",
				"All traffic (including credentials, session cookies, and form data) is transmitted in plaintext and can be intercepted or modified in transit.",
				"Pasang sertifikat TLS yang valid (misalnya dari Let's Encrypt) dan konfigurasikan pengalihan (301 Redirect) otomatis dari HTTP ke HTTPS.",
				"Provision a valid TLS certificate (e.g., via Let's Encrypt) and enforce an automatic 301 redirect from HTTP to HTTPS.",
				fmt.Sprintf("Target URL: %s\nPercobaan koneksi TLS ke %s gagal: %v", targetURL, addr, err),
				targetURL,
				"CWE-319",
				"OWASP A02:2021 - Cryptographic Failures",
				[]string{
					"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
					"https://cwe.mitre.org/data/definitions/319.html",
				},
			))
			return findings, nil
		}
		return findings, fmt.Errorf("koneksi TLS gagal ke %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if isPlainHTTP {
		findings = append(findings, engine.NewFinding(
			models.ModuleTLS,
			"TLS-HTTP-NOT-REDIRECTED",
			host,
			"http-no-redirect",
			models.SeverityMedium,
			models.ConfidenceHigh,
			"Koneksi HTTP Tidak Dialihkan Secara Otomatis ke HTTPS",
			"HTTP Connection Does Not Automatically Redirect to HTTPS",
			"Port HTTPS aktif pada target, tetapi permintaan ke HTTP tidak dialihkan secara otomatis ke HTTPS.",
			"Although HTTPS is available on the host, plain HTTP requests are served directly without redirecting to HTTPS.",
			"Pengguna yang mengetikkan domain tanpa `https://` dapat tetap berada di sesi HTTP yang tidak terenkripsi.",
			"Users navigating without an explicit `https://` prefix may remain on an unencrypted HTTP connection.",
			"Konfigurasikan web server untuk mengalihkan semua request HTTP (port 80) ke HTTPS (port 443) menggunakan HTTP 301 Moved Permanently.",
			"Configure your web server to redirect all HTTP (port 80) traffic to HTTPS (port 443) with an HTTP 301 Moved Permanently status.",
			fmt.Sprintf("Initial URL: %s\nFinal URL: %s", targetURL, safeFinalURL(scanCtx.Baseline, targetURL)),
			targetURL,
			"CWE-319",
			"OWASP A02:2021 - Cryptographic Failures",
			[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"},
		))
	}

	// Inspect X.509 Certificate
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		now := time.Now()

		// 1. Expiration check
		if now.After(leaf.NotAfter) {
			daysAgo := int(math.Ceil(now.Sub(leaf.NotAfter).Hours() / 24))
			findings = append(findings, engine.NewFinding(
				models.ModuleTLS,
				"TLS-CERT-EXPIRED",
				host,
				"cert-expired",
				models.SeverityHigh,
				models.ConfidenceHigh,
				"Sertifikat TLS/SSL Sudah Kedaluwarsa",
				"Expired TLS/SSL Certificate",
				fmt.Sprintf("Sertifikat TLS untuk %s telah kedaluwarsa sejak %s (%d hari yang lalu).", host, leaf.NotAfter.Format("2006-01-02"), daysAgo),
				fmt.Sprintf("The TLS certificate for %s expired on %s (%d days ago).", host, leaf.NotAfter.Format("2006-01-02"), daysAgo),
				"Browser menampilkan peringatan keamanan kepada pengunjung, dan pengguna yang terbiasa mengabaikan peringatan rentan terhadap serangan Man-in-the-Middle.",
				"Browsers display security warnings blocking access, and conditioning users to bypass certificate errors exposes them to Man-in-the-Middle attacks.",
				"Perbarui sertifikat TLS segera dan aktifkan perpanjangan otomatis (mis. certbot / ACME).",
				"Renew the TLS certificate immediately and configure automated renewal (e.g., via ACME / certbot).",
				fmt.Sprintf("Subject: %s\nIssuer: %s\nNotBefore: %s\nNotAfter: %s", leaf.Subject.String(), leaf.Issuer.String(), leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339)),
				targetURL,
				"CWE-298",
				"OWASP A02:2021 - Cryptographic Failures",
				[]string{"https://cwe.mitre.org/data/definitions/298.html"},
			))
		} else {
			daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
			if daysLeft <= 30 {
				findings = append(findings, engine.NewFinding(
					models.ModuleTLS,
					"TLS-CERT-EXPIRING-SOON",
					host,
					"cert-expiring-soon",
					models.SeverityMedium,
					models.ConfidenceHigh,
					fmt.Sprintf("Sertifikat TLS Akan Segera Kedaluwarsa (%d Hari Lagi)", daysLeft),
					fmt.Sprintf("TLS Certificate Expiring Soon (%d Days Remaining)", daysLeft),
					fmt.Sprintf("Sertifikat TLS akan berakhir pada %s (%d hari tersisa).", leaf.NotAfter.Format("2006-01-02"), daysLeft),
					fmt.Sprintf("The TLS certificate will expire on %s (%d days remaining).", leaf.NotAfter.Format("2006-01-02"), daysLeft),
					"Jika sertifikat tidak diperpanjang tepat waktu, layanan web akan mengalami gangguan akses dan peringatan keamanan di browser.",
					"If not renewed in time, users and API clients will experience connection failures and browser security warnings.",
					"Jadwalkan perpanjangan sertifikat sebelum tanggal kedaluwarsa dan periksa otomatisasi ACME.",
					"Renew the certificate before expiration and verify that automated renewal jobs are functioning.",
					fmt.Sprintf("Subject: %s\nNotAfter: %s (%d days remaining)", leaf.Subject.String(), leaf.NotAfter.Format(time.RFC3339), daysLeft),
					targetURL,
					"CWE-298",
					"OWASP A02:2021 - Cryptographic Failures",
					[]string{"https://cwe.mitre.org/data/definitions/298.html"},
				))
			}
		}

		// 2. Hostname verification
		if err := leaf.VerifyHostname(host); err != nil {
			findings = append(findings, engine.NewFinding(
				models.ModuleTLS,
				"TLS-CERT-HOSTNAME-MISMATCH",
				host,
				"cert-hostname-mismatch",
				models.SeverityHigh,
				models.ConfidenceHigh,
				"Hostname Sertifikat TLS Tidak Cocok dengan Domain Target",
				"TLS Certificate Hostname Mismatch",
				fmt.Sprintf("Sertifikat TLS yang disajikan server tidak mencakup nama domain `%s`.", host),
				fmt.Sprintf("The TLS certificate presented by the server is not valid for the hostname `%s`.", host),
				"Ketidakcocokan nama host menandakan kesalahan konfigurasi vhost atau potensi penyadapan koneksi (MITM).",
				"Hostname mismatch indicates a misconfigured virtual host or a potential Man-in-the-Middle interception.",
				"Pastikan Subject Alternative Name (SAN) pada sertifikat TLS mencakup domain dan subdomain yang digunakan.",
				"Ensure the TLS certificate's Subject Alternative Name (SAN) extension includes the exact target domain.",
				fmt.Sprintf("Target Host: %s\nCertificate CN: %s\nDNS SANs: %v\nVerify Error: %v", host, leaf.Subject.CommonName, leaf.DNSNames, err),
				targetURL,
				"CWE-297",
				"OWASP A02:2021 - Cryptographic Failures",
				[]string{"https://cwe.mitre.org/data/definitions/297.html"},
			))
		}

		// 3. Self-signed / Chain trust verification
		isSelfSigned := leaf.Issuer.String() == leaf.Subject.String()
		roots, _ := x509.SystemCertPool()
		intermediates := x509.NewCertPool()
		for _, ic := range state.PeerCertificates[1:] {
			intermediates.AddCert(ic)
		}
		_, chainErr := leaf.Verify(x509.VerifyOptions{
			DNSName:       host,
			Roots:         roots,
			Intermediates: intermediates,
		})

		if isSelfSigned {
			findings = append(findings, engine.NewFinding(
				models.ModuleTLS,
				"TLS-CERT-SELFSIGNED",
				host,
				"cert-selfsigned",
				models.SeverityHigh,
				models.ConfidenceHigh,
				"Sertifikat TLS Ditandatangani Sendiri (Self-Signed Certificate)",
				"Self-Signed TLS Certificate Detected",
				"Server menggunakan sertifikat TLS yang ditandatangani sendiri (self-signed) dan bukan oleh Certificate Authority (CA) publik yang tepercaya.",
				"The server uses a self-signed TLS certificate rather than one issued by a trusted Certificate Authority (CA).",
				"Klien tidak dapat memverifikasi keaslian identitas server, sehingga rentan terhadap pemalsuan sertifikat oleh pihak ketiga.",
				"Clients cannot verify the authenticity of the server identity, leaving connections vulnerable to active Man-in-the-Middle impersonation.",
				"Gunakan sertifikat TLS dari Certificate Authority resmi yang dipercaya oleh sistem operasi dan browser.",
				"Replace the self-signed certificate with one issued by a trusted Certificate Authority.",
				fmt.Sprintf("Subject: %s\nIssuer: %s", leaf.Subject.String(), leaf.Issuer.String()),
				targetURL,
				"CWE-295",
				"OWASP A02:2021 - Cryptographic Failures",
				[]string{"https://cwe.mitre.org/data/definitions/295.html"},
			))
		} else if chainErr != nil && now.Before(leaf.NotAfter) && leaf.VerifyHostname(host) == nil {
			findings = append(findings, engine.NewFinding(
				models.ModuleTLS,
				"TLS-CERT-UNTRUSTED-CHAIN",
				host,
				"cert-untrusted-chain",
				models.SeverityMedium,
				models.ConfidenceHigh,
				"Rantai Sertifikat TLS Tidak Lengkap atau Tidak Dipercaya",
				"Incomplete or Untrusted TLS Certificate Chain",
				"Rantai sertifikat TLS gagal diverifikasi terhadap Root CA sistem (misalnya sertifikat intermediate tidak disertakan).",
				"The TLS certificate chain failed verification against the system Root CA store (e.g., missing intermediate certificate).",
				"Beberapa browser atau klien API (seperti curl, Go, Python, perangkat mobile) akan menolak koneksi karena tidak dapat membangun jalur kepercayaan ke Root CA.",
				"Strict TLS clients (such as mobile browsers, API clients, and CLI tools) will reject the connection when intermediate certificates are missing.",
				"Konfigurasikan web server untuk mengirimkan bundle sertifikat lengkap (`fullchain.pem`) yang mencakup sertifikat leaf dan intermediate.",
				"Configure your web server to serve the complete certificate bundle (`fullchain.pem`), including both leaf and intermediate certificates.",
				fmt.Sprintf("Chain Length: %d\nVerification Error: %v", len(state.PeerCertificates), chainErr),
				targetURL,
				"CWE-295",
				"OWASP A02:2021 - Cryptographic Failures",
				[]string{"https://cwe.mitre.org/data/definitions/295.html"},
			))
		}

		// 4. RSA Key Size check
		if rsaPub, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
			bits := rsaPub.N.BitLen()
			if bits < 2048 {
				findings = append(findings, engine.NewFinding(
					models.ModuleTLS,
					"TLS-WEAK-KEY",
					host,
					"weak-rsa-key",
					models.SeverityHigh,
					models.ConfidenceHigh,
					fmt.Sprintf("Ukuran Kunci Publik RSA Terlalu Lemah (%d bit)", bits),
					fmt.Sprintf("Weak RSA Public Key Size (%d bits)", bits),
					fmt.Sprintf("Sertifikat TLS menggunakan kunci RSA %d-bit yang berada di bawah standar keamanan minimum 2048-bit.", bits),
					fmt.Sprintf("The TLS certificate uses a %d-bit RSA key, which is below the minimum industry standard of 2048 bits.", bits),
					"Kunci RSA di bawah 2048-bit rentan terhadap faktorisasi kriptografi.",
					"RSA keys smaller than 2048 bits are vulnerable to cryptographic factorization.",
					"Terbitkan ulang sertifikat dengan kunci RSA minimal 2048-bit atau ECDSA P-256.",
					"Re-issue the certificate with at least a 2048-bit RSA key or an ECDSA P-256 key.",
					fmt.Sprintf("Public Key Algorithm: RSA (%d bits)", bits),
					targetURL,
					"CWE-326",
					"OWASP A02:2021 - Cryptographic Failures",
					[]string{"https://cwe.mitre.org/data/definitions/326.html"},
				))
			}
		}

		// 5. Weak Signature Algorithm check
		sigAlg := leaf.SignatureAlgorithm.String()
		if strings.Contains(strings.ToUpper(sigAlg), "SHA1") || strings.Contains(strings.ToUpper(sigAlg), "MD5") {
			findings = append(findings, engine.NewFinding(
				models.ModuleTLS,
				"TLS-WEAK-SIGNATURE",
				host,
				"weak-sig-alg",
				models.SeverityHigh,
				models.ConfidenceHigh,
				"Algoritma Tanda Tangan Sertifikat TLS Lemah ("+sigAlg+")",
				"Weak TLS Certificate Signature Algorithm ("+sigAlg+")",
				fmt.Sprintf("Sertifikat TLS ditandatangani menggunakan algoritma hash usang `%s`.", sigAlg),
				fmt.Sprintf("The TLS certificate is signed using the deprecated hash algorithm `%s`.", sigAlg),
				"Algoritma SHA-1 dan MD5 rentan terhadap serangan collision sehingga sertifikat dapat dipalsukan.",
				"SHA-1 and MD5 signature algorithms are vulnerable to collision attacks and rejected by modern browsers.",
				"Terbitkan ulang sertifikat menggunakan algoritma tanda tangan berbasis SHA-256 atau lebih kuat.",
				"Re-issue the certificate using SHA-256 or stronger signature algorithms.",
				fmt.Sprintf("Signature Algorithm: %s", sigAlg),
				targetURL,
				"CWE-328",
				"OWASP A02:2021 - Cryptographic Failures",
				[]string{"https://cwe.mitre.org/data/definitions/328.html"},
			))
		}

		// 6. Informational Certificate & TLS Summary
		cipherName := tls.CipherSuiteName(state.CipherSuite)
		verName := tlsVersionName(state.Version)
		findings = append(findings, engine.NewFinding(
			models.ModuleTLS,
			"TLS-INFO-SUMMARY",
			host,
			"tls-summary",
			models.SeverityInfo,
			models.ConfidenceHigh,
			fmt.Sprintf("Profil TLS & Sertifikat (%s · %s)", verName, leaf.Issuer.CommonName),
			fmt.Sprintf("TLS & Certificate Profile (%s · %s)", verName, leaf.Issuer.CommonName),
			"Ringkasan konfigurasi koneksi TLS dan sertifikat X.509 yang digunakan oleh server target.",
			"Summary of the negotiated TLS connection parameters and X.509 certificate presented by the target server.",
			"Informasi konfigurasi enkripsi transport sebagai referensi audit.",
			"Informational transport encryption baseline for security audit reference.",
			"Pastikan hanya TLS 1.2 dan TLS 1.3 yang diaktifkan serta pantau masa berlaku sertifikat secara berkala.",
			"Ensure only TLS 1.2 and TLS 1.3 remain enabled and monitor certificate expiration dates regularly.",
			fmt.Sprintf(
				"Protocol: %s\nCipher Suite: %s\nSubject: %s\nIssuer: %s\nValid From: %s\nValid Until: %s\nSANs: %s",
				verName,
				cipherName,
				leaf.Subject.String(),
				leaf.Issuer.String(),
				leaf.NotBefore.Format("2006-01-02"),
				leaf.NotAfter.Format("2006-01-02"),
				strings.Join(leaf.DNSNames, ", "),
			),
			targetURL,
			"CWE-319",
			"OWASP A02:2021 - Cryptographic Failures",
			[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"},
		))
	}

	// 7. Check negotiated cipher strength
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	upperCipher := strings.ToUpper(cipherName)
	if strings.Contains(upperCipher, "3DES") || strings.Contains(upperCipher, "RC4") || strings.Contains(upperCipher, "CBC") {
		findings = append(findings, engine.NewFinding(
			models.ModuleTLS,
			"TLS-WEAK-CIPHER",
			host,
			"weak-cipher",
			models.SeverityMedium,
			models.ConfidenceHigh,
			"Cipher Suite TLS Lemah atau Non-AEAD Terdeteksi ("+cipherName+")",
			"Weak or Non-AEAD TLS Cipher Suite Negotiated ("+cipherName+")",
			fmt.Sprintf("Server menegosiasikan cipher suite `%s` yang menggunakan mode CBC/3DES/RC4 tanpa AEAD.", cipherName),
			fmt.Sprintf("The server negotiated the cipher suite `%s`, which relies on legacy CBC/3DES/RC4 modes instead of modern AEAD.", cipherName),
			"Cipher suite non-AEAD atau usang lebih rentan terhadap serangan padding oracle (seperti Lucky13, SWEET32, POODLE).",
			"Legacy and non-AEAD cipher suites are susceptible to padding oracle and block cipher attacks (such as Lucky13 or SWEET32).",
			"Utamakan cipher suite berbasis AEAD seperti `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, dan `ECDHE-ECDSA/RSA-AES128-GCM-SHA256`.",
			"Configure your server to prefer modern AEAD cipher suites (AES-GCM and ChaCha20-Poly1305) with Forward Secrecy (ECDHE).",
			fmt.Sprintf("Negotiated Cipher: %s", cipherName),
			targetURL,
			"CWE-327",
			"OWASP A02:2021 - Cryptographic Failures",
			[]string{"https://ssl-config.mozilla.org/"},
		))
	}

	// 8. Probe deprecated TLS 1.0 and TLS 1.1 support
	var supportedLegacy []string
	for _, ver := range []struct {
		code uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
	} {
		if ctx.Err() != nil {
			break
		}
		if err := scanCtx.Client.WaitRateLimit(ctx); err != nil {
			break
		}
		probeConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 4 * time.Second}, "tcp", addr, &tls.Config{
			ServerName:         host,
			MinVersion:         ver.code,
			MaxVersion:         ver.code,
			InsecureSkipVerify: true,
		})
		if err == nil {
			_ = probeConn.Close()
			supportedLegacy = append(supportedLegacy, ver.name)
		}
	}

	if len(supportedLegacy) > 0 {
		findings = append(findings, engine.NewFinding(
			models.ModuleTLS,
			"TLS-LEGACY-PROTOCOL",
			host,
			"legacy-tls",
			models.SeverityMedium,
			models.ConfidenceHigh,
			"Protokol TLS Usang Masih Diaktifkan ("+strings.Join(supportedLegacy, ", ")+")",
			"Deprecated TLS Protocol Versions Enabled ("+strings.Join(supportedLegacy, ", ")+")",
			fmt.Sprintf("Server masih menerima koneksi menggunakan protokol usang: %s (telah didepresiasi secara resmi oleh RFC 8996).", strings.Join(supportedLegacy, ", ")),
			fmt.Sprintf("The server accepts connections over deprecated protocol versions: %s (officially deprecated by RFC 8996).", strings.Join(supportedLegacy, ", ")),
			"TLS 1.0 dan TLS 1.1 memiliki kelemahan kriptografi (seperti BEAST dan kurangnya dukungan cipher AEAD modern) serta melanggar standar kepatuhan seperti PCI-DSS.",
			"TLS 1.0 and 1.1 lack modern AEAD cipher support, are vulnerable to protocol downgrade/BEAST attacks, and violate compliance standards such as PCI-DSS.",
			"Nonaktifkan TLS 1.0 dan TLS 1.1 pada konfigurasi web server/load balancer; izinkan hanya TLS 1.2 dan TLS 1.3.",
			"Disable TLS 1.0 and TLS 1.1 in your web server or load balancer configuration; enable only TLS 1.2 and TLS 1.3.",
			fmt.Sprintf("Host: %s\nAccepted Legacy Protocols: %s", addr, strings.Join(supportedLegacy, ", ")),
			targetURL,
			"CWE-327",
			"OWASP A02:2021 - Cryptographic Failures",
			[]string{
				"https://datatracker.ietf.org/doc/html/rfc8996",
				"https://ssl-config.mozilla.org/",
			},
		))
	}

	return findings, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func safeFinalURL(b *engine.BaselineResponse, fallback string) string {
	if b != nil && b.FinalURL != "" {
		return b.FinalURL
	}
	return fallback
}
