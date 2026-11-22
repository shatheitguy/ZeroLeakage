package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/dnsserver"
	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
	"github.com/shatheitguy/ZeroLeakage/server/internal/upstream"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	lm := lists.NewManager(dir, log)
	lm.Rebuild(context.Background(), []string{"trackers"}, 0)
	up := upstream.New(upstream.Resolver{}, nil, nil)
	e := dnsserver.NewEngine(lm, up, st, log)
	settings, _ := st.GetSettings(store.DefaultSettings([]string{"trackers"}))
	settings.PublicHostname = "dns.example.com"
	_ = st.PutSettings(settings)
	if err := e.Reload(settings); err != nil {
		t.Fatal(err)
	}
	a := &API{Engine: e, Store: st, Lists: lm, Upstream: up, Log: log, Version: "test"}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return srv
}

type client struct {
	t    *testing.T
	base string
	hc   *http.Client
	auth string
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, hc: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

func (c *client) do(method, path string, body any, out any, csrf bool) int {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, r)
	req.Header.Set("Content-Type", "application/json")
	if csrf {
		req.Header.Set("X-ZL-Request", "1")
	}
	if c.auth != "" {
		req.Header.Set("Authorization", "Bearer "+c.auth)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestSetupLoginRulesAndSync(t *testing.T) {
	srv := newServer(t)
	admin := newClient(t, srv.URL)

	var status map[string]any
	admin.do("GET", "/api/v1/status", nil, &status, false)
	if status["setupNeeded"] != true {
		t.Fatalf("fresh server should need setup: %v", status)
	}
	if code := admin.do("POST", "/api/v1/auth/setup", map[string]string{"username": "admin", "password": "short"}, nil, true); code != 400 {
		t.Fatalf("weak password accepted: %d", code)
	}
	if code := admin.do("POST", "/api/v1/auth/setup", map[string]string{"username": "admin", "password": "correct horse battery"}, nil, true); code != 200 {
		t.Fatalf("setup failed: %d", code)
	}
	if code := admin.do("POST", "/api/v1/auth/setup", map[string]string{"username": "x", "password": "another long pass"}, nil, true); code != 409 {
		t.Fatalf("second setup must be refused: %d", code)
	}
	// CSRF header required for writes
	if code := admin.do("POST", "/api/v1/rules", map[string]string{"kind": "block", "domain": "a.com"}, nil, false); code != 403 {
		t.Fatalf("write without CSRF header should be 403, got %d", code)
	}
	var rule map[string]string
	if code := admin.do("POST", "/api/v1/rules?scope=default", map[string]string{"kind": "block", "domain": "https://Bad.Example.com/path"}, &rule, true); code != 200 || rule["domain"] != "bad.example.com" {
		t.Fatalf("add rule: %d %v", code, rule)
	}
	var chk struct {
		Decision dnsserver.Decision `json:"decision"`
	}
	admin.do("GET", "/api/v1/check?domain=x.bad.example.com", nil, &chk, false)
	if !chk.Decision.Blocked {
		t.Fatalf("check should report blocked: %+v", chk)
	}

	// Sign-up is off by default; turn it on and let a user link two apps.
	user := newClient(t, srv.URL)
	if code := user.do("POST", "/api/v1/auth/signup", map[string]string{"username": "sam", "password": "sam's long password"}, nil, true); code != 403 {
		t.Fatalf("sign-up should be off by default: %d", code)
	}
	var settings store.Settings
	admin.do("GET", "/api/v1/settings", nil, &settings, false)
	settings.AllowSignup = true
	if code := admin.do("PUT", "/api/v1/settings", settings, nil, true); code != 200 {
		t.Fatalf("save settings: %d", code)
	}
	if code := user.do("POST", "/api/v1/auth/signup", map[string]string{"username": "sam", "password": "sam's long password"}, nil, true); code != 200 {
		t.Fatalf("sign-up: %d", code)
	}

	type linked struct {
		Token  string `json:"token"`
		Device struct {
			ID     string `json:"id"`
			DoHURL string `json:"dohUrl"`
		} `json:"device"`
	}
	var phone, laptop linked
	anon := newClient(t, srv.URL)
	if code := anon.do("POST", "/api/v1/devices/link", map[string]string{"username": "sam", "password": "wrong password!!", "deviceName": "Phone"}, nil, false); code != 401 {
		t.Fatalf("link with wrong password: %d", code)
	}
	anon.do("POST", "/api/v1/devices/link", map[string]string{"username": "sam", "password": "sam's long password", "deviceName": "Phone"}, &phone, false)
	anon.do("POST", "/api/v1/devices/link", map[string]string{"username": "sam", "password": "sam's long password", "deviceName": "Laptop"}, &laptop, false)
	if phone.Token == "" || laptop.Token == "" || phone.Device.DoHURL != "https://dns.example.com/dns-query/"+phone.Device.ID {
		t.Fatalf("link failed: %+v %+v", phone, laptop)
	}

	// Phone pushes a rule; laptop pulls it (same user scope).
	p := newClient(t, srv.URL)
	p.auth = phone.Token
	var applied map[string]any
	p.do("PUT", "/api/v1/sync", map[string]any{"rules": []store.Rule{{Kind: "block", Domain: "tiktok.com", UpdatedAt: time.Now().UnixMilli()}}}, &applied, false)
	if applied["applied"].(float64) != 1 {
		t.Fatalf("sync push: %v", applied)
	}
	l := newClient(t, srv.URL)
	l.auth = laptop.Token
	var doc struct {
		Rules []store.Rule `json:"rules"`
	}
	l.do("GET", "/api/v1/sync", nil, &doc, false)
	if len(doc.Rules) != 1 || doc.Rules[0].Domain != "tiktok.com" {
		t.Fatalf("laptop should receive the phone's rule: %+v", doc)
	}
	// Older edit loses (last writer wins).
	p.do("PUT", "/api/v1/sync", map[string]any{"rules": []store.Rule{{Kind: "block", Domain: "tiktok.com", UpdatedAt: 1, Deleted: true}}}, &applied, false)
	if applied["applied"].(float64) != 0 {
		t.Fatalf("stale delete must not win: %v", applied)
	}
	// Bad token
	bad := newClient(t, srv.URL)
	bad.auth = "nope"
	if code := bad.do("GET", "/api/v1/sync", nil, nil, false); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
	// A normal user can't change server settings.
	if code := user.do("PUT", "/api/v1/settings", settings, nil, true); code != 403 {
		t.Fatalf("non-admin settings change: %d", code)
	}
}
