package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/dnsserver"
	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
	"github.com/shatheitguy/ZeroLeakage/server/internal/policy"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
)

func cleanPlatform(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "android", "windows", "ios", "macos", "linux":
		return p
	case "":
		return ""
	}
	return "other"
}

func cleanName(n, def string) string {
	n = strings.TrimSpace(n)
	if n == "" {
		n = def
	}
	if len(n) > 60 {
		n = n[:60]
	}
	return n
}

// linkedResponse is what an app receives after linking (password or pairing code).
func (a *API) linkedResponse(d store.Device, tok string, username string) map[string]any {
	v := a.view(d)
	return map[string]any{
		"token":    tok,
		"device":   map[string]any{"id": d.ID, "name": d.Name, "dohUrl": v.DoHURL, "dotHost": v.DoTHost, "platform": d.Platform},
		"server":   a.serverInfo(),
		"username": username,
	}
}

// linkApp lets an app sign in with username/password and register itself as a device.
func (a *API) linkApp(w http.ResponseWriter, r *http.Request) {
	var b struct {
		credentials
		DeviceName string `json:"deviceName"`
		Platform   string `json:"platform"`
	}
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := a.checkPassword(r, b.credentials)
	if err != nil {
		code := http.StatusUnauthorized
		if err == errTooMany {
			code = http.StatusTooManyRequests
		}
		fail(w, code, err.Error())
		return
	}
	a.createLinked(w, u.ID, u.Username, cleanName(b.DeviceName, "ZeroLeakage app"), cleanPlatform(b.Platform), "user")
}

func (a *API) createLinked(w http.ResponseWriter, userID int64, username, name, platform, scope string) {
	d, err := a.Store.CreateDeviceWith(store.Device{UserID: &userID, Name: name, Kind: "app", Platform: platform, SyncScope: scope})
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	tok, err := a.Store.LinkDevice(d.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Linked = true
	a.reload()
	writeJSON(w, http.StatusCreated, a.linkedResponse(d, tok, username))
}

// pairCode issues a one-time pairing code (10 minutes) owned by the signed-in user.
func (a *API) pairCode(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name  string `json:"name"`
		Scope string `json:"scope"`
	}
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	code, exp, err := a.Store.CreatePairCode(userOf(r).ID, cleanName(b.Name, ""), b.Scope, 10*time.Minute)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"code": code, "expiresAt": exp.UnixMilli()})
}

// pair redeems a pairing code (no account details on the phone). Rate-limited like sign-in.
func (a *API) pair(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Code       string `json:"code"`
		DeviceName string `json:"deviceName"`
		Platform   string `json:"platform"`
	}
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	ip := a.clientIP(r)
	if a.authBlocked(ip) {
		fail(w, http.StatusTooManyRequests, errTooMany.Error())
		return
	}
	pc, err := a.Store.ConsumePairCode(b.Code)
	if err != nil {
		a.recordFailure(ip)
		fail(w, http.StatusUnauthorized, store.ErrBadCode.Error())
		return
	}
	u, err := a.Store.UserByID(pc.UserID)
	if err != nil || u.Disabled {
		fail(w, http.StatusUnauthorized, store.ErrBadCode.Error())
		return
	}
	name := pc.Name
	if name == "" {
		name = cleanName(b.DeviceName, "ZeroLeakage app")
	}
	a.createLinked(w, u.ID, u.Username, name, cleanPlatform(b.Platform), pc.Scope)
}

// ───────────────────────── app sync ─────────────────────────

// syncScope: rules a device syncs. Owned devices share the owner's rules unless paired with scope "device".
func syncScope(d store.Device) string {
	if d.UserID != nil && d.SyncScope != "device" {
		return dnsserver.UserScope(*d.UserID)
	}
	return "device:" + d.ID
}

type customListOut struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Category string `json:"category"`
}

type syncPolicy struct {
	Lists          []string          `json:"lists"`
	CustomLists    []customListOut   `json:"customLists"`
	Services       []string          `json:"services"`
	Categories     []string          `json:"categories"`
	SafeSearch     policy.SafeSearch `json:"safeSearch"`
	BlockMode      string            `json:"blockMode"`
	Schedules      []policy.Schedule `json:"schedules"`
	Guard          syncGuard         `json:"guard"`
	BypassBlocking bool              `json:"bypassBlocking"`
}

type syncGuard struct {
	Enabled          bool `json:"enabled"`
	DropMaliciousIPs bool `json:"dropMaliciousIPs"`
}

type syncLocked struct {
	Lists        []string          `json:"lists"`
	Services     []string          `json:"services"`
	Categories   []string          `json:"categories"`
	BlockDomains []string          `json:"blockDomains"`
	SafeSearch   policy.SafeSearch `json:"safeSearch"`
}

type syncDoc struct {
	Rules         []store.Rule        `json:"rules"`
	Lists         []string            `json:"lists"`
	ServerTime    int64               `json:"serverTime"`
	DeviceID      string              `json:"deviceId"`
	DoHURL        string              `json:"dohUrl,omitempty"`
	DoTHost       string              `json:"dotHost,omitempty"`
	Policy        syncPolicy          `json:"policy"`
	Effective     map[string][]string `json:"effective"`
	Locked        syncLocked          `json:"locked"`
	UserPolicy    policy.Policy       `json:"userPolicy"`
	PolicyVersion string              `json:"policyVersion"`
}

// policyDoc builds the effective policy document for a device (shared by GET and PUT responses).
func (a *API) policyDoc(d store.Device) (syncPolicy, map[string][]string, syncLocked, policy.Policy, string) {
	c := a.Engine.Effective(d.ID)
	net := a.Engine.Effective("")
	netPol := a.Engine.NetworkPolicy()
	eff := c.Effective()
	settings := a.Engine.Settings()

	inEff := map[string]bool{}
	for _, id := range eff.Lists {
		inEff[id] = true
	}
	cls := []customListOut{}
	if cs, err := a.Store.CustomLists(); err == nil {
		for _, x := range cs {
			if inEff[x.ID] {
				cls = append(cls, customListOut{x.ID, x.Name, x.URL, lists.NormalizeCategory(x.Category)})
			}
		}
	}
	for _, x := range eff.CustomLists {
		cls = append(cls, customListOut{x.ID, x.Name, x.URL, x.Category})
	}
	gcfg := syncGuard{}
	if a.Guard != nil && a.Guard.Enabled() {
		gc := a.Guard.Config()
		gcfg = syncGuard{Enabled: true, DropMaliciousIPs: len(gc.DNSFeeds) > 0}
	}
	p := syncPolicy{
		Lists: eff.Lists, CustomLists: cls, Services: eff.Services, Categories: eff.Categories, SafeSearch: eff.SafeSearch,
		BlockMode: settings.BlockMode, Schedules: eff.Schedules, Guard: gcfg, BypassBlocking: settings.BlockBypass != policy.BypassOff,
	}
	allow, block := c.EffectiveRules()
	effective := map[string][]string{"allow": allow, "block": block}
	netBlock := make([]string, 0, len(net.NetBlock))
	for k := range net.NetBlock {
		netBlock = append(netBlock, k)
	}
	sort.Strings(netBlock)
	locked := syncLocked{Lists: append([]string{}, net.BaseLists...), Services: append([]string{}, netPol.Services...),
		Categories: append([]string{}, netPol.Categories...), BlockDomains: netBlock, SafeSearch: netPol.SafeSearch}
	up := a.scopePolicy(policyScopeOf(d))
	b, _ := json.Marshal([]any{p, effective, locked, up})
	h := sha256.Sum256(b)
	return p, effective, locked, up, hex.EncodeToString(h[:8])
}

// policyScopeOf is where a device's own policy edits go: the owner's extras, or the device itself.
func policyScopeOf(d store.Device) string {
	if d.UserID != nil && d.SyncScope != "device" {
		return "user:" + strconv.FormatInt(*d.UserID, 10)
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
	rs := []store.Rule{}
	for _, x := range all {
		if x.UpdatedAt > since {
			rs = append(rs, x)
		}
	}
	v := a.view(d)
	p, eff, locked, up, ver := a.policyDoc(d)
	writeJSON(w, http.StatusOK, syncDoc{Rules: rs, Lists: a.Engine.Settings().EnabledLists, ServerTime: time.Now().UnixMilli(),
		DeviceID: d.ID, DoHURL: v.DoHURL, DoTHost: v.DoTHost, Policy: p, Effective: eff, Locked: locked, UserPolicy: up, PolicyVersion: ver})
}

// syncRule accepts both the server's format {kind, domain, updatedAt, deleted} and the apps'
// {domain, action: allow|block, op: add|remove}.
type syncRule struct {
	Kind      string `json:"kind"`
	Action    string `json:"action"`
	Op        string `json:"op"`
	Domain    string `json:"domain"`
	UpdatedAt int64  `json:"updatedAt"`
	Deleted   bool   `json:"deleted"`
}

// userPolicyPatch: only the fields present are changed.
type userPolicyPatch struct {
	Lists       *[]string            `json:"lists"`
	CustomLists *[]policy.CustomList `json:"customLists"`
	Services    *[]string            `json:"services"`
	Categories  *[]string            `json:"categories"`
	SafeSearch  *policy.SafeSearch   `json:"safeSearch"`
	UpdatedAt   int64                `json:"updatedAt"`
}

func (a *API) putSync(w http.ResponseWriter, r *http.Request) {
	d := deviceOf(r)
	var body struct {
		Rules      []syncRule       `json:"rules"`
		UserPolicy *userPolicyPatch `json:"userPolicy"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if len(body.Rules) > 10_000 {
		fail(w, http.StatusRequestEntityTooLarge, "too many rules in one sync")
		return
	}
	var clean, tombs []store.Rule
	now := time.Now().UnixMilli()
	live := map[string]bool{}
	if cur, err := a.Store.Rules(syncScope(d), false); err == nil {
		for _, x := range cur {
			live[x.Kind+"|"+x.Domain] = true
		}
	}
	for _, x := range body.Rules {
		kind := x.Kind
		if kind == "" {
			kind = x.Action
		}
		dom, ok := normalizeDomain(x.Domain)
		if !ok || (kind != "allow" && kind != "block") {
			continue
		}
		ts := x.UpdatedAt
		if ts <= 0 || ts > now+60_000 { // clamp clocks running ahead
			ts = now
		}
		deleted := x.Deleted || strings.EqualFold(x.Op, "remove") || strings.EqualFold(x.Op, "delete")
		clean = append(clean, store.Rule{Kind: kind, Domain: dom, UpdatedAt: ts, Deleted: deleted})
		if other := map[string]string{"allow": "block", "block": "allow"}[kind]; !deleted && live[other+"|"+dom] { // a domain can't be on both lists
			tombs = append(tombs, store.Rule{Kind: other, Domain: dom, UpdatedAt: ts, Deleted: true})
		}
	}
	n, err := a.Store.MergeRules(syncScope(d), clean)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if m, _ := a.Store.MergeRules(syncScope(d), tombs); m > 0 && n == 0 {
		n = -1 // only tombstones changed: still reload below
	}
	policyApplied := false
	if pp := body.UserPolicy; pp != nil {
		scope := policyScopeOf(d)
		cur := a.scopePolicy(scope)
		ts := pp.UpdatedAt
		if ts <= 0 || ts > now+60_000 {
			ts = now
		}
		if ts >= cur.UpdatedAt { // last writer wins
			if pp.Lists != nil {
				cur.Lists = *pp.Lists
			}
			if pp.CustomLists != nil {
				cur.CustomLists = *pp.CustomLists
			}
			if pp.Services != nil {
				cur.Services = *pp.Services
			}
			if pp.Categories != nil {
				cur.Categories = *pp.Categories
			}
			if pp.SafeSearch != nil {
				cur.SafeSearch = *pp.SafeSearch
			}
			if _, err := a.savePolicy(scope, cur); err != nil {
				fail(w, http.StatusBadRequest, err.Error())
				return
			}
			policyApplied = true
		}
	}
	if n != 0 && !policyApplied {
		a.reload()
	}
	n = max(n, 0)
	d, _ = a.Store.Device(d.ID)
	_, _, _, _, ver := a.policyDoc(d)
	writeJSON(w, http.StatusOK, map[string]any{"applied": n, "userPolicyApplied": policyApplied, "serverTime": time.Now().UnixMilli(), "policyVersion": ver})
}
