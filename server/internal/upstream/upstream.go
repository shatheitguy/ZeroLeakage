// Package upstream forwards allowed queries to encrypted DNS-over-HTTPS resolvers with failover.
package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolver is one DoH endpoint.
type Resolver struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Known resolvers (same set as the apps). DNSSEC-validating unless noted.
var Known = []Resolver{
	{"cloudflare", "Cloudflare", "https://1.1.1.1/dns-query"},
	{"quad9", "Quad9", "https://dns.quad9.net/dns-query"},
	{"mullvad", "Mullvad", "https://dns.mullvad.net/dns-query"},
	{"adguard", "AdGuard DNS", "https://dns.adguard-dns.com/dns-query"},
	{"cf_security", "Cloudflare Security", "https://security.cloudflare-dns.com/dns-query"},
	{"google", "Google Public DNS", "https://dns.google/dns-query"},
	{"controld", "Control D (free)", "https://freedns.controld.com/p0"},
	{"dnssb", "DNS.SB", "https://doh.dns.sb/dns-query"},
}

// Find returns a known resolver by id.
func Find(id string) (Resolver, bool) {
	for _, r := range Known {
		if r.ID == id {
			return r, true
		}
	}
	return Resolver{}, false
}

// Answer is a resolved response plus where it came from.
type Answer struct {
	Msg      *dns.Msg
	Resolver string
	Latency  time.Duration
}

// Client tries the primary resolver, then backups, skipping recently failed ones for a minute.
// Optionally falls back to plain DNS (e.g. the router) when every encrypted resolver is unreachable.
type Client struct {
	http *http.Client

	mu        sync.Mutex
	primary   Resolver
	backups   []Resolver
	plain     []string // "host:53"
	downUntil map[string]time.Time
}

func New(primary Resolver, backups []Resolver, plainFallback []string) *Client {
	tr := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 3 * time.Second,
	}
	return &Client{
		http:      &http.Client{Transport: tr, Timeout: 4 * time.Second},
		primary:   primary,
		backups:   backups,
		plain:     plainFallback,
		downUntil: map[string]time.Time{},
	}
}

// Configure swaps the resolver set at runtime.
func (c *Client) Configure(primary Resolver, backups []Resolver, plainFallback []string) {
	c.mu.Lock()
	c.primary, c.backups, c.plain = primary, backups, plainFallback
	c.mu.Unlock()
}

func (c *Client) candidates() []Resolver {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]bool{}
	var all, healthy []Resolver
	now := time.Now()
	for _, r := range append([]Resolver{c.primary}, c.backups...) {
		if r.URL == "" || seen[r.URL] {
			continue
		}
		seen[r.URL] = true
		all = append(all, r)
		if now.After(c.downUntil[r.URL]) {
			healthy = append(healthy, r)
		}
	}
	if len(healthy) == 0 {
		return all
	}
	return healthy
}

func (c *Client) markDown(url string) {
	c.mu.Lock()
	c.downUntil[url] = time.Now().Add(time.Minute)
	c.mu.Unlock()
}

// Exchange resolves q. The query's ID is preserved in the answer.
func (c *Client) Exchange(ctx context.Context, q *dns.Msg) (*Answer, error) {
	var lastErr error
	for _, r := range c.candidates() {
		start := time.Now()
		m, err := c.doh(ctx, r.URL, q)
		if err == nil {
			c.mu.Lock()
			delete(c.downUntil, r.URL)
			c.mu.Unlock()
			return &Answer{m, r.Name, time.Since(start)}, nil
		}
		lastErr = fmt.Errorf("%s: %w", r.Name, err)
		c.markDown(r.URL)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	c.mu.Lock()
	plain := append([]string{}, c.plain...)
	c.mu.Unlock()
	for _, addr := range plain {
		start := time.Now()
		cl := &dns.Client{Timeout: 3 * time.Second}
		m, _, err := cl.ExchangeContext(ctx, q, addr)
		if err == nil {
			return &Answer{m, "Plain DNS " + addr, time.Since(start)}, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream configured")
	}
	return nil, lastErr
}

func (c *Client) doh(ctx context.Context, url string, q *dns.Msg) (*dns.Msg, error) {
	id := q.Id
	out := q.Copy()
	out.Id = 0 // RFC 8484: cache-friendly
	wire, err := out.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		return nil, err
	}
	m.Id = id
	return m, nil
}
