// Package api is the REST API and web dashboard of the ZeroLeakage server.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/shatheitguy/ZeroLeakage/server/internal/clients"
	"github.com/shatheitguy/ZeroLeakage/server/internal/dnsserver"
	"github.com/shatheitguy/ZeroLeakage/server/internal/filter"
	"github.com/shatheitguy/ZeroLeakage/server/internal/guard"
	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
	"github.com/shatheitguy/ZeroLeakage/server/internal/netinfo"
	"github.com/shatheitguy/ZeroLeakage/server/internal/policy"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
	"github.com/shatheitguy/ZeroLeakage/server/internal/upstream"
)

//go:embed web
var webFS embed.FS

const sessionCookie = "zl_session"

// API wires HTTP routes to the engine and store.
type API struct {
	Engine     *dnsserver.Engine
	Store      *store.Store
	Lists      *lists.Manager
	Upstream   *upstream.Client
	Guard      *guard.Guard     // optional
	Clients    *clients.Tracker // optional
	Log        *slog.Logger
	Version    string
	TrustProxy bool

	loginMu  sync.Mutex
	failures map[string][]time.Time // ip -> recent failed logins / pairing attempts

	buildMu   sync.Mutex
	lastBuilt []string
}

// Handler returns the full HTTP handler (dashboard, API and DoH).
func (a *API) Handler() http.Handler {
	a.failures = map[string][]time.Time{}
	mux := http.NewServeMux()
	doh := dnsserver.DoHHandler(a.Engine, a.TrustProxy)
	mux.Handle("/dns-query", doh)
	mux.Handle("/dns-query/", doh)

	mux.HandleFunc("GET /api/v1/status", a.status)
	mux.HandleFunc("POST /api/v1/auth/setup", a.setup)
	mux.HandleFunc("POST /api/v1/auth/login", a.login)
	mux.HandleFunc("POST /api/v1/auth/signup", a.signup)
	mux.HandleFunc("POST /api/v1/auth/logout", a.logout)
	mux.HandleFunc("GET /api/v1/me", a.auth(a.me))

	mux.HandleFunc("GET /api/v1/settings", a.admin(a.getSettings))
	mux.HandleFunc("PUT /api/v1/settings", a.admin(a.putSettings))
	mux.HandleFunc("GET /api/v1/resolvers", a.auth(a.resolvers))

	mux.HandleFunc("GET /api/v1/lists", a.auth(a.getLists))
	mux.HandleFunc("PUT /api/v1/lists", a.admin(a.putLists))
	mux.HandleFunc("POST /api/v1/lists/refresh", a.admin(a.refreshLists))
	mux.HandleFunc("POST /api/v1/lists/custom", a.admin(a.addCustomList))
	mux.HandleFunc("DELETE /api/v1/lists/custom/{id}", a.admin(a.deleteCustomList))

	mux.HandleFunc("GET /api/v1/rules", a.auth(a.getRules))
	mux.HandleFunc("POST /api/v1/rules", a.auth(a.addRule))
	mux.HandleFunc("DELETE /api/v1/rules", a.auth(a.deleteRule))
	mux.HandleFunc("GET /api/v1/check", a.auth(a.check))

	mux.HandleFunc("GET /api/v1/devices", a.auth(a.getDevices))
	mux.HandleFunc("POST /api/v1/devices", a.auth(a.createDevice))
	mux.HandleFunc("PUT /api/v1/devices/{id}", a.auth(a.updateDevice))
	mux.HandleFunc("DELETE /api/v1/devices/{id}", a.auth(a.deleteDevice))
	mux.HandleFunc("POST /api/v1/devices/{id}/link", a.auth(a.linkDevice))
	mux.HandleFunc("POST /api/v1/devices/link", a.linkApp) // app signs in with username/password
	mux.HandleFunc("POST /api/v1/devices/pair-code", a.auth(a.pairCode))
	mux.HandleFunc("POST /api/v1/devices/pair", a.pair) // app redeems a pairing code

	mux.HandleFunc("GET /api/v1/sync", a.device(a.getSync))
	mux.HandleFunc("PUT /api/v1/sync", a.device(a.putSync))

	mux.HandleFunc("GET /api/v1/stats", a.auth(a.stats))
	mux.HandleFunc("GET /api/v1/querylog", a.auth(a.querylog))
	mux.HandleFunc("GET /api/v1/reports", a.auth(a.reports))

	mux.HandleFunc("GET /api/v1/users", a.admin(a.users))
	mux.HandleFunc("POST /api/v1/users", a.admin(a.createUser))
	mux.HandleFunc("PUT /api/v1/users/{id}", a.admin(a.updateUser))
	mux.HandleFunc("DELETE /api/v1/users/{id}", a.admin(a.deleteUser))

	mux.HandleFunc("GET /api/v1/services", a.auth(a.services))
	mux.HandleFunc("GET /api/v1/categories", a.auth(a.categories))
	mux.HandleFunc("GET /api/v1/policy", a.auth(a.getPolicy))
	mux.HandleFunc("PUT /api/v1/policy", a.auth(a.putPolicy))
	mux.HandleFunc("GET /api/v1/rewrites", a.admin(a.getRewrites))
	mux.HandleFunc("POST /api/v1/rewrites", a.admin(a.addRewrite))
	mux.HandleFunc("DELETE /api/v1/rewrites/{id}", a.admin(a.deleteRewrite))
	mux.HandleFunc("GET /api/v1/clients", a.admin(a.getClients))
	mux.HandleFunc("POST /api/v1/clients/name", a.admin(a.nameClient))

	mux.HandleFunc("GET /api/v1/guard", a.admin(a.guardStatus))
	mux.HandleFunc("PUT /api/v1/guard/config", a.admin(a.guardConfig))
	mux.HandleFunc("POST /api/v1/guard/bans", a.admin(a.guardBan))
	mux.HandleFunc("DELETE /api/v1/guard/bans/{id}", a.admin(a.guardUnban))
	mux.HandleFunc("POST /api/v1/guard/unban", a.admin(a.guardUnbanIP))
	mux.HandleFunc("POST /api/v1/guard/feeds/refresh", a.admin(a.guardRefresh))
	mux.HandleFunc("GET /api/v1/guard/alerts", a.admin(a.guardAlerts))
	mux.HandleFunc("GET /api/v1/guard/bouncers", a.admin(a.getBouncers))
	mux.HandleFunc("POST /api/v1/guard/bouncers", a.admin(a.createBouncer))
	mux.HandleFunc("DELETE /api/v1/guard/bouncers/{id}", a.admin(a.deleteBouncer))
	mux.HandleFunc("GET /api/v1/guard/blocklist.txt", a.blocklist)

	static, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServerFS(static))
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/dns-query") {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		h.ServeHTTP(w, r)
	})
}

// ───────────────────────── helpers ─────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(v)
}

type userKey struct{}
type deviceKey struct{}

func userOf(r *http.Request) store.User     { return r.Context().Value(userKey{}).(store.User) }
func deviceOf(r *http.Request) store.Device { return r.Context().Value(deviceKey{}).(store.Device) }

func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			fail(w, http.StatusUnauthorized, "sign in required")
			return
		}
		u, err := a.Store.SessionUser(c.Value)
		if err != nil {
			fail(w, http.StatusUnauthorized, "session expired")
			return
		}
		// CSRF: state-changing requests must come from our own page.
		if r.Method != http.MethodGet && r.Header.Get("X-ZL-Request") != "1" {
			fail(w, http.StatusForbidden, "missing request header")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
	}
}

func (a *API) admin(next http.HandlerFunc) http.HandlerFunc {
	return a.auth(func(w http.ResponseWriter, r *http.Request) {
		if !userOf(r).IsAdmin {
			fail(w, http.StatusForbidden, "admin only")
			return
		}
		next(w, r)
	})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if tok, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(tok)
	}
	return ""
}

// device authenticates a linked app by its bearer token.
func (a *API) device(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			fail(w, http.StatusUnauthorized, "device token required")
			return
		}
		d, err := a.Store.DeviceByToken(tok)
		if err != nil {
			fail(w, http.StatusUnauthorized, "unknown device token")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), deviceKey{}, d)))
	}
}

// reload recompiles policy and starts a list rebuild when the set of lists in use changed.
func (a *API) reload() {
	if err := a.Engine.Reload(a.Engine.Settings()); err != nil {
		a.Log.Error("reload failed", "err", err)
	}
	a.rebuildIfNeeded(false)
}

// rebuildIfNeeded downloads/rebuilds filter lists when the needed set changed (or always when force).
func (a *API) rebuildIfNeeded(force bool) {
	ids := a.Engine.ListIDs()
	a.buildMu.Lock()
	changed := force || !slices.Equal(ids, a.lastBuilt)
	if changed {
		a.lastBuilt = ids
	}
	a.buildMu.Unlock()
	if changed {
		go a.Lists.Rebuild(context.Background(), ids, 0)
	}
}

// MarkBuilt records the list set main() already built at start-up.
func (a *API) MarkBuilt(ids []string) {
	a.buildMu.Lock()
	a.lastBuilt = ids
	a.buildMu.Unlock()
}

// canManage: admins manage everything; users manage their own devices.
func canManage(u store.User, d store.Device) bool {
	return u.IsAdmin || (d.UserID != nil && *d.UserID == u.ID)
}

// ownDeviceIDs lists the device ids a non-admin may see (nil for admins = everything).
func (a *API) ownDeviceIDs(u store.User) []string {
	if u.IsAdmin {
		return nil
	}
	ds, _ := a.Store.Devices(&u.ID)
	ids := []string{}
	for _, d := range ds {
		ids = append(ids, d.ID)
	}
	return ids
}

var domainRe = regexp.MustCompile(`^[a-z0-9_.-]+$`)

func normalizeDomain(raw string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	if i := strings.IndexAny(d, "/:?#"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimSuffix(strings.TrimPrefix(d, "*."), ".")
	if !domainRe.MatchString(d) {
		return "", false
	}
	return filter.CleanDomain(d)
}

func (a *API) clientIP(r *http.Request) string { return dnsserver.ClientIP(r, a.TrustProxy) }

// ───────────────────────── status & auth ─────────────────────────

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	n, _ := a.Store.UserCount()
	st := a.Engine.Settings()
	writeJSON(w, http.StatusOK, map[string]any{
		"name":        "ZeroLeakage Server",
		"version":     a.Version,
		"uptimeSec":   int64(time.Since(a.Engine.Started).Seconds()),
		"setupNeeded": n == 0,
		"allowSignup": st.AllowSignup,
		"queries":     a.Engine.Counters.Queries.Load(),
		"blocked":     a.Engine.Counters.Blocked.Load(),
		"rules":       a.Lists.Index().TotalRules(),
		"hostname":    st.PublicHostname,
	})
}

func (a *API) serverInfo() map[string]any {
	return map[string]any{"name": "ZeroLeakage Server", "version": a.Version, "hostname": a.Engine.Settings().PublicHostname}
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c credentials) valid() error {
	if len(strings.TrimSpace(c.Username)) < 3 || len(c.Username) > 40 {
		return errors.New("username must be 3-40 characters")
	}
	if len(c.Password) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	return nil
}

func (a *API) startSession(w http.ResponseWriter, r *http.Request, u store.User) {
	tok, err := a.Store.NewSession(u.ID, 30*24*time.Hour)
	if err != nil {
		fail(w, http.StatusInternalServerError, "could not start session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", MaxAge: 30 * 24 * 3600,
	})
	writeJSON(w, http.StatusOK, u)
}

func (a *API) setup(w http.ResponseWriter, r *http.Request) {
	if n, _ := a.Store.UserCount(); n > 0 {
		fail(w, http.StatusConflict, "already set up")
		return
	}
	var c credentials
	if err := readJSON(r, &c); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := c.valid(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
	u, err := a.Store.CreateUser(strings.TrimSpace(c.Username), string(hash), true)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	a.startSession(w, r, u)
}

// tooManyFailures: max 10 failed logins / pairing attempts per IP per 15 minutes.
func (a *API) tooManyFailures(ip string, record bool) bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	var recent []time.Time
	for _, t := range a.failures[ip] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	if record {
		recent = append(recent, time.Now())
	}
	if len(recent) == 0 {
		delete(a.failures, ip)
	} else {
		a.failures[ip] = recent
	}
	return len(recent) >= 10
}

// authBlocked: an address with a Guard ban may not sign in (LAN clients only for brute-force bans,
// so a quarantined family device can still reach the dashboard's sign-in).
func (a *API) authBlocked(ip string) bool {
	if a.tooManyFailures(ip, false) {
		return true
	}
	addr, ok := netinfo.Parse(ip)
	if !ok || a.Guard == nil {
		return false
	}
	if d := a.Guard.Banned(addr); d != nil {
		return !netinfo.IsLAN(addr) || d.Scenario == guard.ScenarioBruteForce
	}
	return false
}

func (a *API) recordFailure(ip string) {
	a.tooManyFailures(ip, true)
	if addr, ok := netinfo.Parse(ip); ok && a.Guard != nil {
		a.Guard.LoginFailure(addr)
	}
}

var errTooMany = errors.New("too many attempts, try again in 15 minutes")

func (a *API) checkPassword(r *http.Request, c credentials) (store.User, error) {
	ip := a.clientIP(r)
	if a.authBlocked(ip) {
		return store.User{}, errTooMany
	}
	u, err := a.Store.UserByName(strings.TrimSpace(c.Username))
	if err == nil && bcrypt.CompareHashAndPassword([]byte(u.PassHash()), []byte(c.Password)) == nil {
		if u.Disabled {
			return store.User{}, errors.New("this account is disabled")
		}
		return u, nil
	}
	a.recordFailure(ip)
	return store.User{}, errors.New("wrong username or password")
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := readJSON(r, &c); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := a.checkPassword(r, c)
	if err != nil {
		code := http.StatusUnauthorized
		if err == errTooMany {
			code = http.StatusTooManyRequests
		}
		fail(w, code, err.Error())
		return
	}
	a.startSession(w, r, u)
}

func (a *API) signup(w http.ResponseWriter, r *http.Request) {
	if !a.Engine.Settings().AllowSignup {
		fail(w, http.StatusForbidden, "sign-up is turned off on this server")
		return
	}
	var c credentials
	if err := readJSON(r, &c); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := c.valid(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
	u, err := a.Store.CreateUser(strings.TrimSpace(c.Username), string(hash), false)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	a.startSession(w, r, u)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.Store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *API) me(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, userOf(r)) }

// ───────────────────────── users (admin) ─────────────────────────

func (a *API) users(w http.ResponseWriter, r *http.Request) {
	us, err := a.Store.Users()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if us == nil {
		us = []store.User{}
	}
	writeJSON(w, http.StatusOK, us)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var b struct {
		credentials
		IsAdmin bool `json:"isAdmin"`
	}
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := b.valid(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(b.Password), bcrypt.DefaultCost)
	u, err := a.Store.CreateUser(strings.TrimSpace(b.Username), string(hash), b.IsAdmin)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (a *API) targetUser(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, err := a.Store.UserByID(id)
	if err != nil {
		fail(w, http.StatusNotFound, "user not found")
		return u, false
	}
	return u, true
}

// lastAdmin reports whether u is the only enabled admin.
func (a *API) lastAdmin(u store.User) bool {
	n, _ := a.Store.AdminCount()
	return u.IsAdmin && !u.Disabled && n <= 1
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	u, ok := a.targetUser(w, r)
	if !ok {
		return
	}
	var b struct {
		Password *string `json:"password"`
		Disabled *bool   `json:"disabled"`
		IsAdmin  *bool   `json:"isAdmin"`
	}
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	self := u.ID == userOf(r).ID
	if (b.Disabled != nil && *b.Disabled) || (b.IsAdmin != nil && !*b.IsAdmin) {
		if self {
			fail(w, http.StatusBadRequest, "you can't disable or demote your own account")
			return
		}
		if a.lastAdmin(u) {
			fail(w, http.StatusBadRequest, "keep at least one admin")
			return
		}
	}
	if b.Password != nil {
		if len(*b.Password) < 10 {
			fail(w, http.StatusBadRequest, "password must be at least 10 characters")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(*b.Password), bcrypt.DefaultCost)
		if err := a.Store.SetUserPassword(u.ID, string(hash)); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if b.Disabled != nil {
		_ = a.Store.SetUserDisabled(u.ID, *b.Disabled)
	}
	if b.IsAdmin != nil {
		_ = a.Store.SetUserAdmin(u.ID, *b.IsAdmin)
	}
	u, _ = a.Store.UserByID(u.ID)
	writeJSON(w, http.StatusOK, u)
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := a.targetUser(w, r)
	if !ok {
		return
	}
	if u.ID == userOf(r).ID {
		fail(w, http.StatusBadRequest, "you can't delete your own account")
		return
	}
	if a.lastAdmin(u) {
		fail(w, http.StatusBadRequest, "keep at least one admin")
		return
	}
	if err := a.Store.DeleteUser(u.ID); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reload()
	w.WriteHeader(http.StatusNoContent)
}

// ───────────────────────── settings & resolvers ─────────────────────────

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.Engine.Settings())
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request) {
	cur := a.Engine.Settings()
	next := cur
	if err := readJSON(r, &next); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	next.EnabledLists = cur.EnabledLists // lists have their own endpoint
	if next.BlockMode != "nxdomain" && next.BlockMode != "null_ip" {
		next.BlockMode = "nxdomain"
	}
	if next.RetentionDays < 1 || next.RetentionDays > 365 {
		next.RetentionDays = 7
	}
	switch next.BlockBypass {
	case policy.BypassOff, policy.BypassLAN, policy.BypassAll:
	default:
		next.BlockBypass = policy.BypassLAN
	}
	if v := strings.TrimSpace(next.LocalPTRResolver); v != "" {
		host := v
		if h, _, err := splitHostPort(v); err == nil {
			host = h
		}
		addr, ok := netinfo.Parse(host)
		if !ok || !netinfo.IsLAN(addr) {
			fail(w, http.StatusBadRequest, "the reverse-DNS resolver must be a LAN address (e.g. your router 192.168.1.1)")
			return
		}
		next.LocalPTRResolver = v
	}
	if _, ok := upstream.Find(next.Upstream); !ok {
		if u, err := url.Parse(next.Upstream); err != nil || u.Scheme != "https" || u.Host == "" {
			fail(w, http.StatusBadRequest, "upstream must be a known resolver or an https:// DoH URL")
			return
		}
	}
	if err := a.Store.PutSettings(next); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if next.Upstream != cur.Upstream || !slices.Equal(next.PlainFallback, cur.PlainFallback) {
		a.Engine.ClearCache()
	}
	ConfigureUpstream(a.Upstream, next)
	_ = a.Engine.Reload(next)
	writeJSON(w, http.StatusOK, next)
}

// ConfigureUpstream applies the upstream settings (also used at start-up).
func ConfigureUpstream(c *upstream.Client, st store.Settings) {
	primary, ok := upstream.Find(st.Upstream)
	if !ok {
		primary = upstream.Resolver{ID: "custom", Name: "Custom DoH", URL: st.Upstream}
	}
	var backups []upstream.Resolver
	for _, id := range []string{"cloudflare", "quad9", "google"} {
		if r, ok := upstream.Find(id); ok {
			backups = append(backups, r)
		}
	}
	c.Configure(primary, backups, st.PlainFallback)
}

func (a *API) resolvers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, upstream.Known)
}

// ───────────────────────── lists ─────────────────────────

type listView struct {
	lists.List
	Enabled      bool          `json:"enabled"`
	InUse        bool          `json:"inUse"` // loaded because some policy needs it
	CategoryName string        `json:"categoryName"`
	Status       *lists.Status `json:"status,omitempty"`
}

func (a *API) getLists(w http.ResponseWriter, r *http.Request) {
	enabled := map[string]bool{}
	for _, id := range a.Engine.Settings().EnabledLists {
		enabled[id] = true
	}
	inUse := map[string]bool{}
	for _, id := range a.Engine.ListIDs() {
		inUse[id] = true
	}
	statuses := a.Lists.Status()
	out := []listView{}
	for _, l := range a.Lists.All() {
		if l.Owner != "" { // users' own lists are shown in their policy, not here
			continue
		}
		v := listView{List: l, Enabled: enabled[l.ID], InUse: inUse[l.ID], CategoryName: lists.CategoryName(l.Category)}
		if s, ok := statuses[l.ID]; ok {
			v.Status = &s
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"lists": out, "totalRules": a.Lists.Index().TotalRules()})
}

func (a *API) putLists(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled []string `json:"enabled"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	known := map[string]bool{}
	for _, l := range a.Lists.All() {
		if l.Owner == "" {
			known[l.ID] = true
		}
	}
	ids := []string{}
	for _, id := range body.Enabled {
		if known[id] && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	st := a.Engine.Settings()
	st.EnabledLists = ids
	if err := a.Store.PutSettings(st); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = a.Engine.Reload(st)
	a.rebuildIfNeeded(true)
	writeJSON(w, http.StatusAccepted, map[string]any{"enabled": ids, "rebuilding": true})
}

func (a *API) refreshLists(w http.ResponseWriter, r *http.Request) {
	ids := a.Engine.ListIDs()
	go a.Lists.Rebuild(context.Background(), ids, time.Minute)
	writeJSON(w, http.StatusAccepted, map[string]bool{"refreshing": true})
}

func (a *API) addCustomList(w http.ResponseWriter, r *http.Request) {
	var c store.CustomList
	if err := readJSON(r, &c); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		fail(w, http.StatusBadRequest, "list URL must be http(s)")
		return
	}
	c.URL = u.String()
	if strings.TrimSpace(c.Name) == "" {
		c.Name = u.Host
	}
	c.Category = lists.NormalizeCategory(c.Category)
	c.ID = "custom_" + store.RandomToken(4)
	if err := a.Store.AddCustomList(c); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reload()
	writeJSON(w, http.StatusCreated, c)
}

func (a *API) deleteCustomList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = a.Store.DeleteCustomList(id)
	st := a.Engine.Settings()
	if i := slices.Index(st.EnabledLists, id); i >= 0 {
		st.EnabledLists = slices.Delete(slices.Clone(st.EnabledLists), i, i+1)
		_ = a.Store.PutSettings(st)
		_ = a.Engine.Reload(st)
	}
	a.reload()
	w.WriteHeader(http.StatusNoContent)
}

// SyncCustomLists is kept for callers that set custom lists before the first Reload.
func SyncCustomLists(m *lists.Manager, cs []store.CustomList) {
	var ls []lists.List
	for _, c := range cs {
		ls = append(ls, lists.List{ID: c.ID, Name: c.Name, URL: c.URL, Category: lists.NormalizeCategory(c.Category), Group: "Custom", Custom: true})
	}
	m.SetCustom(ls)
}

// ───────────────────────── rules ─────────────────────────

// scopeFor resolves ?scope= for the caller: "default" (admin), "user" (own), "device:<id>" (own device).
func (a *API) scopeFor(r *http.Request) (string, bool) {
	u := userOf(r)
	s := r.URL.Query().Get("scope")
	switch {
	case s == "" || s == "default":
		return "default", u.IsAdmin
	case s == "user":
		return dnsserver.UserScope(u.ID), true
	case strings.HasPrefix(s, "user:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(s, "user:"), 10, 64)
		return s, err == nil && (u.IsAdmin || id == u.ID)
	case strings.HasPrefix(s, "device:"):
		d, err := a.Store.Device(strings.TrimPrefix(s, "device:"))
		return s, err == nil && canManage(u, d)
	}
	return "", false
}

func (a *API) getRules(w http.ResponseWriter, r *http.Request) {
	scope, ok := a.scopeFor(r)
	if !ok {
		fail(w, http.StatusForbidden, "not allowed")
		return
	}
	rs, err := a.Store.Rules(scope, false)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rs == nil {
		rs = []store.Rule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scope": scope, "rules": rs})
}

type ruleBody struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
}

func (a *API) changeRule(w http.ResponseWriter, r *http.Request, deleted bool) {
	scope, ok := a.scopeFor(r)
	if !ok {
		fail(w, http.StatusForbidden, "not allowed")
		return
	}
	var b ruleBody
	if err := readJSON(r, &b); err != nil || (b.Kind != "allow" && b.Kind != "block") {
		fail(w, http.StatusBadRequest, "kind must be allow or block")
		return
	}
	d, ok := normalizeDomain(b.Domain)
	if !ok {
		fail(w, http.StatusBadRequest, "that isn't a valid domain")
		return
	}
	if err := a.Store.SetRule(scope, b.Kind, d, deleted); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !deleted { // a domain can't be on both lists
		other := map[string]string{"allow": "block", "block": "allow"}[b.Kind]
		_ = a.Store.SetRule(scope, other, d, true)
	}
	a.reload()
	writeJSON(w, http.StatusOK, map[string]string{"scope": scope, "kind": b.Kind, "domain": d})
}

func (a *API) addRule(w http.ResponseWriter, r *http.Request)    { a.changeRule(w, r, false) }
func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) { a.changeRule(w, r, true) }

func (a *API) check(w http.ResponseWriter, r *http.Request) {
	d, ok := normalizeDomain(r.URL.Query().Get("domain"))
	if !ok {
		fail(w, http.StatusBadRequest, "that isn't a valid domain")
		return
	}
	dev := r.URL.Query().Get("device")
	if dev != "" && !userOf(r).IsAdmin {
		dd, err := a.Store.Device(dev)
		if err != nil || !canManage(userOf(r), dd) {
			fail(w, http.StatusForbidden, "not your device")
			return
		}
	}
	client := r.URL.Query().Get("client")
	if client == "" {
		client = a.clientIP(r)
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": d, "decision": a.Engine.DecideFor(dev, client, d, 1)})
}

// ───────────────────────── devices ─────────────────────────

type deviceView struct {
	store.Device
	DoHURL   string `json:"dohUrl,omitempty"`
	DoTHost  string `json:"dotHost,omitempty"`
	LastSeen int64  `json:"lastSeen"`
	Owner    string `json:"owner,omitempty"`
}

func (a *API) view(d store.Device) deviceView {
	v := deviceView{Device: d, LastSeen: d.LastSeen}
	if h := a.Engine.Settings().PublicHostname; h != "" {
		v.DoHURL = "https://" + h + "/dns-query/" + d.ID
		v.DoTHost = d.ID + "." + h
	}
	return v
}

func (a *API) getDevices(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	var filterUser *int64
	if !u.IsAdmin {
		filterUser = &u.ID
	}
	ds, err := a.Store.Devices(filterUser)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	names := map[int64]string{}
	if u.IsAdmin {
		us, _ := a.Store.Users()
		for _, x := range us {
			names[x.ID] = x.Username
		}
	}
	out := make([]deviceView, 0, len(ds))
	for _, d := range ds {
		v := a.view(d)
		if d.UserID != nil {
			v.Owner = names[*d.UserID]
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

type deviceBody struct {
	Name   string   `json:"name"`
	IPs    []string `json:"ips"`
	Paused *bool    `json:"paused"`
}

func cleanIPs(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && len(s) < 50 {
			out = append(out, s)
		}
	}
	return out
}

func (a *API) createDevice(w http.ResponseWriter, r *http.Request) {
	var b deviceBody
	if err := readJSON(r, &b); err != nil || strings.TrimSpace(b.Name) == "" {
		fail(w, http.StatusBadRequest, "name required")
		return
	}
	u := userOf(r)
	kind := "app"
	ips := cleanIPs(b.IPs)
	if len(ips) > 0 {
		kind = "lan"
		if !u.IsAdmin {
			fail(w, http.StatusForbidden, "only the admin can map network IPs")
			return
		}
	}
	d, err := a.Store.CreateDevice(&u.ID, strings.TrimSpace(b.Name), kind, ips)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reload()
	writeJSON(w, http.StatusCreated, a.view(d))
}

func (a *API) ownDevice(w http.ResponseWriter, r *http.Request) (store.Device, bool) {
	d, err := a.Store.Device(r.PathValue("id"))
	if err != nil || !canManage(userOf(r), d) {
		fail(w, http.StatusNotFound, "device not found")
		return d, false
	}
	return d, true
}

func (a *API) updateDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := a.ownDevice(w, r)
	if !ok {
		return
	}
	var b deviceBody
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if strings.TrimSpace(b.Name) != "" {
		d.Name = strings.TrimSpace(b.Name)
	}
	if b.IPs != nil {
		if !userOf(r).IsAdmin {
			fail(w, http.StatusForbidden, "only the admin can map network IPs")
			return
		}
		d.IPs = cleanIPs(b.IPs)
	}
	if b.Paused != nil {
		// pausing switches off the network baseline for that device, so only the admin may do it
		if !userOf(r).IsAdmin {
			fail(w, http.StatusForbidden, "only the admin can pause protection")
			return
		}
		d.Paused = *b.Paused
	}
	if err := a.Store.UpdateDevice(d); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reload()
	writeJSON(w, http.StatusOK, a.view(d))
}

func (a *API) deleteDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := a.ownDevice(w, r)
	if !ok {
		return
	}
	_ = a.Store.DeleteDevice(d.ID)
	a.reload()
	w.WriteHeader(http.StatusNoContent)
}

// linkDevice issues an app token from the dashboard (shown once, e.g. as a QR code).
func (a *API) linkDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := a.ownDevice(w, r)
	if !ok {
		return
	}
	tok, err := a.Store.LinkDevice(d.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reload()
	writeJSON(w, http.StatusOK, map[string]any{"device": a.view(d), "token": tok, "server": a.serverInfo()})
}

// ───────────────────────── stats & log ─────────────────────────

func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*30 {
		hours = 24
	}
	u := userOf(r)
	st, err := a.Store.StatsFor(time.Now().Add(-time.Duration(hours)*time.Hour), a.ownDeviceIDs(u))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{"hours": hours, "stats": st, "rules": a.Lists.Index().TotalRules()}
	if u.IsAdmin {
		out["live"] = map[string]int64{
			"queries": a.Engine.Counters.Queries.Load(), "blocked": a.Engine.Counters.Blocked.Load(),
			"cached": a.Engine.Counters.Cached.Load(), "errors": a.Engine.Counters.Errors.Load(),
		}
	} else {
		out["live"] = map[string]int64{"queries": st.Total, "blocked": st.Blocked}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) querylog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.QueryFilter{DeviceID: q.Get("device"), Search: q.Get("search"), Client: q.Get("client")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	if b := q.Get("blocked"); b != "" {
		v := b == "1" || b == "true"
		f.Blocked = &v
	}
	f.Devices = a.ownDeviceIDs(userOf(r)) // users only see their own devices
	rows, err := a.Store.Queries(f)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []store.QueryEntry{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (a *API) reports(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hours, _ := strconv.Atoi(q.Get("hours"))
	if hours <= 0 || hours > 24*90 {
		hours = 24
	}
	bucket := time.Hour
	if hours > 48 {
		bucket = 24 * time.Hour
	}
	u := userOf(r)
	f := store.ReportFilter{Since: time.Now().Add(-time.Duration(hours) * time.Hour), Bucket: bucket, DeviceID: q.Get("device"), Devices: a.ownDeviceIDs(u)}
	if u.IsAdmin {
		f.Client = q.Get("client")
	}
	rep, err := a.Store.Report(f)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hours": hours, "report": rep})
}
