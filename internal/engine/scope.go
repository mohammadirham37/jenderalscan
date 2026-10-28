package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// TargetScope represents the validated and scope-locked target for a scan.
type TargetScope struct {
	RawInput       string
	NormalizedURL  string
	BaseURL        string // scheme://host[:port]
	Scheme         string
	Host           string // host[:port]
	Hostname       string // lowercase hostname without port
	Port           string
	Path           string
	StrictHostLock bool
}

// ParseAndValidateTarget parses, normalizes, and validates a target URL.
func ParseAndValidateTarget(raw string, strictLock bool) (*TargetScope, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("URL target tidak boleh kosong / Target URL cannot be empty")
	}

	if !strings.Contains(trimmed, "://") {
		// Default to https:// unless localhost or explicit IP with http port
		if strings.HasPrefix(trimmed, "localhost") || strings.HasPrefix(trimmed, "127.0.0.1") {
			trimmed = "http://" + trimmed
		} else {
			trimmed = "https://" + trimmed
		}
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("URL target tidak valid: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("skema URL %q tidak didukung (gunakan http atau https)", scheme)
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return nil, errors.New("hostname target tidak valid / invalid target hostname")
	}
	if strings.ContainsAny(hostname, " \t\r\n/\\@") {
		return nil, errors.New("hostname mengandung karakter tidak valid")
	}

	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	hostWithPort := parsed.Host
	if hostWithPort == "" {
		hostWithPort = hostname
	}

	baseURL := fmt.Sprintf("%s://%s", scheme, hostWithPort)
	cleanPath := parsed.Path
	if cleanPath == "" {
		cleanPath = "/"
	}

	normalizedURL := baseURL + cleanPath
	if parsed.RawQuery != "" {
		normalizedURL += "?" + parsed.RawQuery
	}

	return &TargetScope{
		RawInput:       raw,
		NormalizedURL:  normalizedURL,
		BaseURL:        baseURL,
		Scheme:         scheme,
		Host:           hostWithPort,
		Hostname:       hostname,
		Port:           port,
		Path:           cleanPath,
		StrictHostLock: strictLock,
	}, nil
}

// IsInScope verifies whether a candidate URL belongs to the locked target scope.
func (t *TargetScope) IsInScope(candidateURL string) bool {
	u, err := url.Parse(candidateURL)
	if err != nil {
		return false
	}
	if u.Hostname() == "" {
		// Relative URL is in scope
		return true
	}
	candHost := strings.ToLower(u.Hostname())
	return candHost == t.Hostname
}

// ResolvePath joins a relative path onto the target's BaseURL safely within scope.
func (t *TargetScope) ResolvePath(relPath string) string {
	if !strings.HasPrefix(relPath, "/") {
		relPath = "/" + relPath
	}
	return t.BaseURL + relPath
}

// AddressWithPort returns host:port suitable for net.Dial.
func (t *TargetScope) AddressWithPort(portOverride string) string {
	p := t.Port
	if portOverride != "" {
		p = portOverride
	}
	return net.JoinHostPort(t.Hostname, p)
}

// MakeFingerprint creates a deterministic SHA-256 fingerprint for deduplicating and diffing findings.
func MakeFingerprint(module string, ruleID string, targetHost string, discriminator string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(module)))
	h.Write([]byte("|"))
	h.Write([]byte(strings.ToLower(ruleID)))
	h.Write([]byte("|"))
	h.Write([]byte(strings.ToLower(targetHost)))
	h.Write([]byte("|"))
	h.Write([]byte(discriminator))
	return hex.EncodeToString(h.Sum(nil))[:24]
}
