package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"jenderalscan/internal/models"

	"golang.org/x/time/rate"
)

// BaselineResponse holds the initial probe response of the target so multiple modules can inspect it without duplicate requests.
type BaselineResponse struct {
	StatusCode    int
	Status        string
	Headers       http.Header
	Cookies       []*http.Cookie
	RawSetCookies []string
	Body          []byte
	FinalURL      string
	TLSState      *tls.ConnectionState
	RedirectChain []string
	ResponseTime  time.Duration
}

// ScopedClient wraps http.Client with rate limiting, scope lock enforcement, and request telemetry.
type ScopedClient struct {
	httpClient   *http.Client
	noRedirClient *http.Client
	limiter      *rate.Limiter
	scope        *TargetScope
	settings     models.AppSettings
	requestsSent atomic.Int64
}

// NewScopedClient constructs a rate-limited, scope-locked HTTP client.
func NewScopedClient(scope *TargetScope, settings models.AppSettings) (*ScopedClient, error) {
	rps := settings.RateLimitRPS
	if rps <= 0 {
		rps = 10
	}
	timeout := time.Duration(settings.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !settings.VerifyTLS, // TLS module performs strict certificate validation separately
		},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       30 * time.Second,
	}

	if settings.ProxyURL != "" {
		proxyURL, err := url.Parse(settings.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("proxy URL tidak valid: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	sc := &ScopedClient{
		limiter:  rate.NewLimiter(rate.Limit(rps), max(1, rps)),
		scope:    scope,
		settings: settings,
	}

	sc.httpClient = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			// Enforce Scope Lock: do not follow redirects outside the target hostname
			if !scope.IsInScope(req.URL.String()) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	sc.noRedirClient = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return sc, nil
}

// RequestsSent returns the total HTTP/network requests executed by this client.
func (c *ScopedClient) RequestsSent() int64 {
	return c.requestsSent.Load()
}

// WaitRateLimit blocks until the rate limiter permits another request/probe or context is cancelled.
func (c *ScopedClient) WaitRateLimit(ctx context.Context) error {
	if err := c.limiter.Wait(ctx); err != nil {
		return err
	}
	c.requestsSent.Add(1)
	return nil
}

// Do executes a rate-limited, scope-checked HTTP request with configured headers and retries.
func (c *ScopedClient) Do(ctx context.Context, req *http.Request, followRedirects bool) (*http.Response, []byte, error) {
	if !c.scope.IsInScope(req.URL.String()) {
		return nil, nil, fmt.Errorf("scope lock blocked out-of-scope URL: %s", req.URL.String())
	}

	if req.Header.Get("User-Agent") == "" {
		ua := c.settings.UserAgent
		if ua == "" {
			ua = models.DefaultSettings().UserAgent
		}
		req.Header.Set("User-Agent", ua)
	}
	for k, v := range c.settings.CustomHeaders {
		if k != "" && req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	client := c.httpClient
	if !followRedirects {
		client = c.noRedirClient
	}

	maxAttempts := max(1, c.settings.MaxRetries+1)
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.WaitRateLimit(ctx); err != nil {
			return nil, nil, err
		}

		reqClone := req.Clone(ctx)
		resp, err := client.Do(reqClone)
		if err != nil {
			lastErr = err
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, nil, err
			}
			continue
		}

		// Read up to 2MB max to avoid memory exhaustion on large responses
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		_ = resp.Body.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			lastErr = readErr
			continue
		}
		return resp, body, nil
	}

	return nil, nil, lastErr
}

// Get performs a rate-limited GET request within scope.
func (c *ScopedClient) Get(ctx context.Context, targetURL string, followRedirects bool) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, nil, err
	}
	return c.Do(ctx, req, followRedirects)
}

// FetchBaseline fetches the initial target response and collects cookies across redirects.
func (c *ScopedClient) FetchBaseline(ctx context.Context) (*BaselineResponse, error) {
	start := time.Now()
	currentURL := c.scope.NormalizedURL

	var redirectChain []string
	var allCookies []*http.Cookie
	var rawSetCookies []string
	var lastResp *http.Response
	var lastBody []byte

	for hop := 0; hop < 5; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return nil, err
		}
		resp, body, err := c.Do(ctx, req, false)
		if err != nil {
			if hop == 0 && c.scope.Scheme == "https" {
				// Fallback check if target only speaks HTTP on the given host
				return nil, err
			}
			return nil, err
		}
		lastResp = resp
		lastBody = body
		allCookies = append(allCookies, resp.Cookies()...)
		rawSetCookies = append(rawSetCookies, resp.Header.Values("Set-Cookie")...)

		loc := resp.Header.Get("Location")
		if loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			nextURL, err := resp.Request.URL.Parse(loc)
			if err == nil && c.scope.IsInScope(nextURL.String()) {
				redirectChain = append(redirectChain, nextURL.String())
				currentURL = nextURL.String()
				continue
			}
		}
		break
	}

	if lastResp == nil {
		return nil, errors.New("tidak ada respons dari target / no response from target")
	}

	return &BaselineResponse{
		StatusCode:    lastResp.StatusCode,
		Status:        lastResp.Status,
		Headers:       lastResp.Header,
		Cookies:       allCookies,
		RawSetCookies: rawSetCookies,
		Body:          lastBody,
		FinalURL:      currentURL,
		TLSState:      lastResp.TLS,
		RedirectChain: redirectChain,
		ResponseTime:  time.Since(start),
	}, nil
}
