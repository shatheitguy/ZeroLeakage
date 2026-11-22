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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/shatheitguy/ZeroLeakage/server/internal/dnsserver"
	"github.com/shatheitguy/ZeroLeakage/server/internal/filter"
	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
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
	Log        *slog.Logger
	Version    string
	TrustProxy bool

	loginMu  sync.Mutex
	failures map[string][]time.Time // ip -> recent failed logins
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

	mux.HandleFunc("GET /api/v1/sync", a.device(a.getSync))
	mux.HandleFunc("PUT /api/v1/sync", a.device(a.putSync))

	mux.HandleFunc("GET /api/v1/stats", a.auth(a.stats))
	mux.HandleFunc("GET /api/v1/querylog", a.auth(a.querylog))
	mux.HandleFunc("GET /api/v1/users", a.admin(a.users))

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

func fail(w http.ResponseWriter, code int, msg string) { writeJSON(w, code, map[string]string{"error": msg}) }

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

// device authenticates a linked app by its bearer token.
func (a *API) device(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" || tok == r.Header.Get("Authorization") {
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

func (a *API) reload() {
	if err := a.Engine.Reload(a.Engine.Settings()); err != nil {
		a.Log.Error("reload failed", "err", err)
	}
}

// canManage: admins manage everything; users manage their own devices.
func canManage(u store.User, d store.Device) bool {
	return u.IsAdmin || (d.UserID != nil && *d.UserID == u.ID)
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

// tooManyFailures: max 10 failed logins per IP per 15 minutes.
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
	a.failures[ip] = recent
	return len(recent) >= 10
}

func (a *API) checkPassword(r *http.Request, c credentials) (store.User, error) {
	ip := dnsserver.ClientIP(r, a.TrustProxy)
	if a.tooManyFailures(ip, false) {
		return store.User{}, errors.New("too many attempts, try again in 15 minutes")
	}
	u, err := a.Store.UserByName(strings.TrimSpace(c.Username))
	if err == nil && bcrypt.CompareHashAndPassword([]byte(u.PassHash()), []byte(c.Password)) == nil {
		return u, nil
	}
	a.tooManyFailures(ip, true)
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
		fail(w, http.StatusUnauthorized, err.Error())
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
	Enabled bool          `json:"enabled"`
	Status  *lists.Status `json:"status,omitempty"`
}

func (a *API) getLists(w http.ResponseWriter, r *http.Request) {
	enabled := map[string]bool{}
	for _, id := range a.Engine.Settings().EnabledLists {
		enabled[id] = true
	}
	statuses := a.Lists.Status()
	var out []listView
	for _, l := range a.Lists.All() {
		v := listView{List: l, Enabled: enabled[l.ID]}
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
		known[l.ID] = true
	}
	var ids []string
	for _, id := range body.Enabled {
		if known[id] {
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
	go a.Lists.Rebuild(context.Background(), ids, 0)
	writeJSON(w, http.StatusAccepted, map[string]any{"enabled": ids, "rebuilding": true})
}

func (a *API) refreshLists(w http.ResponseWriter, r *http.Request) {
	go a.Lists.Rebuild(context.Background(), a.Engine.Settings().EnabledLists, time.Minute)
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
	if c.Category == "" {
		c.Category = "Custom"
	}
	c.ID = "custom_" + store.RandomToken(4)
	if err := a.Store.AddCustomList(c); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.syncCustomLists()
	writeJSON(w, http.StatusCreated, c)
}

func (a *API) deleteCustomList(w http.ResponseWriter, r *http.Request) {
	_ = a.Store.DeleteCustomList(r.PathValue("id"))
	a.syncCustomLists()
	w.WriteHeader(http.StatusNoContent)
}

// syncCustomLists pushes custom lists from the store into the list manager.
func (a *API) syncCustomLists() {
	cs, _ := a.Store.CustomLists()
	SyncCustomLists(a.Lists, cs)
}

func SyncCustomLists(m *lists.Manager, cs []store.CustomList) {
	var ls []lists.List
	for _, c := range cs {
		ls = append(ls, lists.List{ID: c.ID, Name: c.Name, URL: c.URL, Category: c.Category, Group: "Custom", Custom: true})
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
	writeJSON(w, http.StatusOK, map[string]any{"domain": d, "decision": a.Engine.Decide(r.URL.Query().Get("device"), d)})
}

// ───────────────────────── devices ─────────────────────────

type deviceView struct {
	store.Device
	DoHURL   string `json:"dohUrl,omitempty"`
	DoTHost  string `json:"dotHost,omitempty"`
	LastSeen int64  `json:"lastSeen"`
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
	out := make([]deviceView, 0, len(ds))
	for _, d := range ds {
		out = append(out, a.view(d))
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
	writeJSON(w, http.StatusOK, map[string]any{"device": a.view(d), "token": tok})
}

// linkApp lets an app sign in with username/password and register itself as a device.
func (a *API) linkApp(w http.ResponseWriter, r *http.Request) {
	var b struct {
		credentials
		DeviceName string `json:"deviceName"`
	}
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := a.checkPassword(r, b.credentials)
	if err != nil {
		fail(w, http.StatusUnauthorized, err.Error())
		return
	}
	name := strings.TrimSpace(b.DeviceName)
	if name == "" {
		name = "ZeroLeakage app"
	}
	d, err := a.Store.CreateDevice(&u.ID, name, "app", nil)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	tok, err := a.Store.LinkDevice(d.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reload()
	writeJSON(w, http.StatusCreated, map[string]any{"device": a.view(d), "token": tok})
}

// ───────────────────────── app sync ─────────────────────────

type syncDoc struct {
	Rules       []store.Rule `json:"rules"`
	Lists       []string     `json:"lists"`
	ServerTime  int64        `json:"serverTime"`
	DeviceID    string       `json:"deviceId"`
	DoHURL      string       `json:"dohUrl,omitempty"`
	DoTHost     string       `json:"dotHost,omitempty"`
}

// syncScope: an app owned by a user syncs the user's rules (shared by all their devices);
// an unowned device syncs its own.
func syncScope(d store.Device) string {
	if d.UserID != nil {
		return dnsserver.UserScope(*d.UserID)
	}
	return "device:" + d.ID
}

func (a *API) getSync(w http.ResponseWriter, r *http.Request) {
	d := deviceOf(r)
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	all, err := a.Store.Rules(syncScope(d), true)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	var rs []store.Rule
	for _, x := range all {
		if x.UpdatedAt > since {
			rs = append(rs, x)
		}
	}
	v := a.view(d)
	writeJSON(w, http.StatusOK, syncDoc{Rules: rs, Lists: a.Engine.Settings().EnabledLists, ServerTime: time.Now().UnixMilli(),
		DeviceID: d.ID, DoHURL: v.DoHURL, DoTHost: v.DoTHost})
}

func (a *API) putSync(w http.ResponseWriter, r *http.Request) {
	d := deviceOf(r)
	var body struct {
		Rules []store.Rule `json:"rules"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	var clean []store.Rule
	now := time.Now().UnixMilli()
	for _, x := range body.Rules {
		dom, ok := normalizeDomain(x.Domain)
		if !ok || (x.Kind != "allow" && x.Kind != "block") {
			continue
		}
		if x.UpdatedAt <= 0 || x.UpdatedAt > now+60_000 { // clamp clocks running ahead
			x.UpdatedAt = now
		}
		x.Domain = dom
		clean = append(clean, x)
	}
	if len(clean) > 10_000 {
		fail(w, http.StatusRequestEntityTooLarge, "too many rules in one sync")
		return
	}
	n, err := a.Store.MergeRules(syncScope(d), clean)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n > 0 {
		a.reload()
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": n, "serverTime": time.Now().UnixMilli()})
}

// ───────────────────────── stats & log ─────────────────────────

func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*30 {
		hours = 24
	}
	st, err := a.Store.Stats(time.Now().Add(-time.Duration(hours) * time.Hour))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hours": hours, "stats": st,
		"live": map[string]int64{
			"queries": a.Engine.Counters.Queries.Load(), "blocked": a.Engine.Counters.Blocked.Load(),
			"cached": a.Engine.Counters.Cached.Load(), "errors": a.Engine.Counters.Errors.Load(),
		},
		"rules": a.Lists.Index().TotalRules(),
	})
}

func (a *API) querylog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.QueryFilter{DeviceID: q.Get("device"), Search: q.Get("search")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	if b := q.Get("blocked"); b != "" {
		v := b == "1" || b == "true"
		f.Blocked = &v
	}
	u := userOf(r)
	if !u.IsAdmin { // users only see their own devices
		ds, _ := a.Store.Devices(&u.ID)
		own := map[string]bool{}
		for _, d := range ds {
			own[d.ID] = true
		}
		if f.DeviceID == "" || !own[f.DeviceID] {
			writeJSON(w, http.StatusOK, []store.QueryEntry{})
			return
		}
	}
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

func (a *API) users(w http.ResponseWriter, r *http.Request) {
	us, err := a.Store.Users()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, us)
}
