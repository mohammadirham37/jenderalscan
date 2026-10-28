package modules

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"jenderalscan/internal/engine"
	"jenderalscan/internal/models"
)

// PortsModule performs a lightweight, rate-limited check of common web and management/database ports on the target host.
type PortsModule struct{}

func NewPortsModule() *PortsModule {
	return &PortsModule{}
}

func (m *PortsModule) ID() models.ModuleID {
	return models.ModulePorts
}

func (m *PortsModule) Name() string {
	return "Port & Service Ringan"
}

type portCheckDef struct {
	Port        int
	Service     string
	Category    string // "web" or "sensitive"
	Severity    models.Severity
	DescID      string
	DescEN      string
	ImpactID    string
	ImpactEN    string
	RecID       string
	RecEN       string
}

var commonPorts = []portCheckDef{
	{Port: 80, Service: "HTTP", Category: "web", Severity: models.SeverityInfo},
	{Port: 443, Service: "HTTPS", Category: "web", Severity: models.SeverityInfo},
	{Port: 8080, Service: "HTTP-Alt", Category: "web", Severity: models.SeverityInfo},
	{Port: 8443, Service: "HTTPS-Alt", Category: "web", Severity: models.SeverityInfo},
	{
		Port:     21,
		Service:  "FTP",
		Category: "sensitive",
		Severity: models.SeverityMedium,
		DescID:   "Port 21 (FTP) terbuka pada host target.",
		DescEN:   "Port 21 (FTP) is open on the target host.",
		ImpactID: "Protokol FTP standar mengirimkan username dan password tanpa enkripsi serta sering menjadi sasaran brute-force.",
		ImpactEN: "Standard FTP transmits credentials in cleartext and increases the host's external attack surface.",
		RecID:    "Nonaktifkan layanan FTP jika tidak diperlukan, atau ganti dengan SFTP dan batasi akses melalui firewall.",
		RecEN:    "Disable FTP if unused, or migrate to SFTP and restrict access via firewall rules.",
	},
	{
		Port:     22,
		Service:  "SSH",
		Category: "sensitive",
		Severity: models.SeverityLow,
		DescID:   "Port 22 (SSH) terbuka ke jaringan pada host target.",
		DescEN:   "Port 22 (SSH) is reachable on the target host.",
		ImpactID: "Port administrasi jarak jauh yang terbuka ke publik terus-menerus menjadi target pemindaian otomatis.",
		ImpactEN: "Publicly reachable SSH endpoints are continuously targeted by automated credential stuffing scans.",
		RecID:    "Pastikan autentikasi berbasis kunci publik (nonaktifkan `PasswordAuthentication`), gunakan VPN/bastion host, atau batasi IP sumber di firewall.",
		RecEN:    "Enforce key-based authentication (`PasswordAuthentication no`) and restrict SSH access to trusted management IPs or a VPN/bastion.",
	},
	{
		Port:     23,
		Service:  "Telnet",
		Category: "sensitive",
		Severity: models.SeverityHigh,
		DescID:   "Port 23 (Telnet) terbuka pada host target.",
		DescEN:   "Port 23 (Telnet) is open on the target host.",
		ImpactID: "Telnet tidak memiliki enkripsi sama sekali sehingga seluruh sesi administrasi dapat disadap.",
		ImpactEN: "Telnet transmits all administrative traffic and credentials in plaintext.",
		RecID:    "Matikan layanan Telnet segera dan tutup port 23 di firewall.",
		RecEN:    "Disable the Telnet service immediately and block port 23 at the firewall.",
	},
	{
		Port:     3306,
		Service:  "MySQL / MariaDB",
		Category: "sensitive",
		Severity: models.SeverityHigh,
		DescID:   "Port database 3306 (MySQL/MariaDB) terbuka dan dapat dijangkau dari luar.",
		DescEN:   "Database port 3306 (MySQL/MariaDB) is open and externally reachable.",
		ImpactID: "Database produksi tidak seharusnya terekspos langsung ke jaringan publik karena rentan terhadap percobaan autentikasi paksa dan eksploitasi layanan.",
		ImpactEN: "Direct exposure of database ports to untrusted networks risks unauthorized access and service exploitation.",
		RecID:    "Ikat MySQL ke `127.0.0.1` (`bind-address = 127.0.0.1`) atau jaringan privat internal, dan blokir port 3306 pada firewall publik.",
		RecEN:    "Bind MySQL to `127.0.0.1` (`bind-address = 127.0.0.1`) or an internal VPC interface, and block port 3306 on public firewalls.",
	},
	{
		Port:     5432,
		Service:  "PostgreSQL",
		Category: "sensitive",
		Severity: models.SeverityHigh,
		DescID:   "Port database 5432 (PostgreSQL) terbuka dan dapat dijangkau dari luar.",
		DescEN:   "Database port 5432 (PostgreSQL) is open and externally reachable.",
		ImpactID: "Mengekspos layanan database secara langsung meningkatkan risiko kompromi data.",
		ImpactEN: "Exposing PostgreSQL directly to external networks significantly increases the risk of unauthorized data access.",
		RecID:    "Batasi `listen_addresses` di `postgresql.conf` ke localhost/subnet internal dan tutup port 5432 di firewall publik.",
		RecEN:    "Restrict `listen_addresses` in `postgresql.conf` to localhost/internal subnets and close port 5432 on external firewalls.",
	},
	{
		Port:     6379,
		Service:  "Redis",
		Category: "sensitive",
		Severity: models.SeverityHigh,
		DescID:   "Port in-memory store 6379 (Redis) terbuka pada host target.",
		DescEN:   "Port 6379 (Redis) is open and reachable on the target host.",
		ImpactID: "Instalasi Redis yang terekspos ke jaringan sering tidak memiliki autentikasi kuat dan dapat menyebabkan pencurian sesi atau kompromi server.",
		ImpactEN: "Externally exposed Redis instances frequently allow unauthorized access to cached session data or server configuration.",
		RecID:    "Aktifkan `protected-mode yes`, bind ke `127.0.0.1`, wajibkan autentikasi ACL, dan tutup port 6379 pada firewall.",
		RecEN:    "Enable `protected-mode yes`, bind to `127.0.0.1`, enforce ACL passwords, and block port 6379 at the network perimeter.",
	},
	{
		Port:     27017,
		Service:  "MongoDB",
		Category: "sensitive",
		Severity: models.SeverityHigh,
		DescID:   "Port database 27017 (MongoDB) terbuka pada host target.",
		DescEN:   "Database port 27017 (MongoDB) is open on the target host.",
		ImpactID: "Eksposur port MongoDB ke publik berisiko tinggi terhadap pengambilalihan data.",
		ImpactEN: "Public exposure of MongoDB ports poses a critical risk of unauthorized database access.",
		RecID:    "Atur `net.bindIp: 127.0.0.1` pada `mongod.conf` dan blokir akses eksternal ke port 27017.",
		RecEN:    "Set `net.bindIp: 127.0.0.1` in `mongod.conf` and block external traffic to port 27017.",
	},
}

func (m *PortsModule) Run(ctx context.Context, scanCtx *engine.ScanContext) ([]models.Finding, error) {
	host := scanCtx.Target.Hostname
	targetURL := scanCtx.Target.NormalizedURL

	var findings []models.Finding
	var openWebPorts []string

	for _, p := range commonPorts {
		if ctx.Err() != nil {
			break
		}
		if err := scanCtx.Client.WaitRateLimit(ctx); err != nil {
			break
		}

		addr := net.JoinHostPort(host, strconv.Itoa(p.Port))
		dialer := net.Dialer{Timeout: 1200 * time.Millisecond}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}

		// Passive banner read (max 300ms)
		banner := ""
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 128)
		if n, readErr := conn.Read(buf); readErr == nil && n > 0 {
			banner = strings.TrimSpace(string(buf[:n]))
		}
		_ = conn.Close()

		if p.Category == "web" {
			openWebPorts = append(openWebPorts, fmt.Sprintf("%d/tcp (%s)", p.Port, p.Service))
			continue
		}

		evidence := fmt.Sprintf("Host: %s\nOpen Port: %d/tcp (%s)", host, p.Port, p.Service)
		if banner != "" {
			evidence += fmt.Sprintf("\nService Banner: %s", sanitizeBanner(banner))
		}

		findings = append(findings, engine.NewFinding(
			models.ModulePorts,
			fmt.Sprintf("PORT-EXPOSED-%d", p.Port),
			host,
			fmt.Sprintf("port-%d", p.Port),
			p.Severity,
			models.ConfidenceHigh,
			fmt.Sprintf("Port %d/tcp (%s) Terbuka pada Host Target", p.Port, p.Service),
			fmt.Sprintf("Open Port %d/tcp (%s) Detected on Target Host", p.Port, p.Service),
			p.DescID,
			p.DescEN,
			p.ImpactID,
			p.ImpactEN,
			p.RecID,
			p.RecEN,
			evidence,
			targetURL,
			"CWE-200",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://cwe.mitre.org/data/definitions/200.html"},
		))
	}

	if len(openWebPorts) > 0 {
		findings = append(findings, engine.NewFinding(
			models.ModulePorts,
			"PORT-WEB-SUMMARY",
			host,
			"port-web-summary",
			models.SeverityInfo,
			models.ConfidenceHigh,
			fmt.Sprintf("Port Layanan Web Terbuka (%s)", strings.Join(openWebPorts, ", ")),
			fmt.Sprintf("Open Web Service Ports (%s)", strings.Join(openWebPorts, ", ")),
			"Ringkasan port layanan web standar yang merespons koneksi TCP pada host target.",
			"Summary of standard web service ports accepting TCP connections on the target host.",
			"Informasi inventaris permukaan jaringan pada host target.",
			"Informational network surface inventory for the target host.",
			"Pastikan hanya port layanan yang benar-benar digunakan di produksi yang dibuka pada firewall.",
			"Ensure only required production web ports are exposed through the firewall.",
			fmt.Sprintf("Host: %s\nOpen Web Ports: %s", host, strings.Join(openWebPorts, ", ")),
			targetURL,
			"CWE-200",
			"OWASP A05:2021 - Security Misconfiguration",
			[]string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
		))
	}

	return findings, nil
}

func sanitizeBanner(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		} else if r == '\n' || r == '\r' {
			b.WriteRune(' ')
		}
	}
	return strings.TrimSpace(b.String())
}
