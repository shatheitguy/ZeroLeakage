package api

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/dnsserver"
	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
	"github.com/shatheitguy/ZeroLeakage/server/internal/netinfo"
	"github.com/shatheitguy/ZeroLeakage/server/internal/policy"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
)

func splitHostPort(s string) (string, string, error) { return net.SplitHostPort(s) }

// ───────────────────────── catalogs ─────────────────────────

func (a *API) services(w http.ResponseWriter, r *http.Request) {
	bypass := policy.BypassDomains()
	writeJSON(w, http.StatusOK, map[string]any{"services": policy.Services, "bypassDomains": bypass})
}

type categoryView struct {
	lists.Category
	Lists         []string `json:"lists"`         // every catalog list in this category
	EnabledLists  []string `json:"enabledLists"`  // network-enabled lists in this category
	NetworkActive bool     `json:"networkActive"` // blocked network-wide (category on or a list enabled)
}

func (a *API) categories(w http.ResponseWriter, r *http.Request) {
	net := a.Engine.NetworkPolicy()
	enabled := a.Engine.Settings().EnabledLists
	var out []categoryView
	for _, c := range lists.Categories {
		v := categoryView{Category: c, Lists: []string{}, EnabledLists: []string{}}
		if v.AutoLists == nil {
			v.AutoLists = []string{}
		}
		for _, l := range a.Lists.All() {
			if l.Category == c.ID && l.Owner == "" {
				v.Lists = append(v.Lists, l.ID)
				if slices.Contains(enabled, l.ID) {
					v.EnabledLists = append(v.EnabledLists, l.ID)
				}
			}
		}
		v.NetworkActive = slices.Contains(net.Categories, c.ID) || len(v.EnabledLists) > 0
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// ───────────────────────── policies ─────────────────────────

// policyScope resolves ?scope= to a storage key: "default", "user:<id>" or "device:<id>".
func (a *API) policyScope(r *http.Request, write bool) (scope string, ok bool) {
	u := userOf(r)
	s := r.URL.Query().Get("scope")
	switch {
	case s == "" || s == "default":
		return "default", !write || u.IsAdmin
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

func (a *API) scopePolicy(scope string) policy.Policy {
	if scope == "default" {
		return a.Engine.NetworkPolicy()
	}
	if id, ok := strings.CutPrefix(scope, "user:"); ok {
		n, _ := strconv.ParseInt(id, 10, 64)
		if p, ok := a.Engine.UserPolicy(n); ok {
			return p
		}
	}
	if id, ok := strings.CutPrefix(scope, "device:"); ok {
		if p, ok := a.Engine.DevicePolicy(id); ok {
			return p
		}
	}
	return policy.Policy{Lists: []string{}, Services: []string{}, Categories: []string{}, Schedules: []policy.Schedule{}, SafeSearch: policy.SafeSearch{YouTube: policy.YouTubeOff}}
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) {
	scope, ok := a.policyScope(r, false)
	if !ok {
		fail(w, http.StatusForbidden, "not allowed")
		return
	}
	out := map[string]any{
		"scope": scope, "policy": a.scopePolicy(scope), "network": a.Engine.NetworkPolicy(),
		"networkLists": a.Engine.Settings().EnabledLists, "editable": scope != "default" || userOf(r).IsAdmin,
	}
	if id, ok := strings.CutPrefix(scope, "device:"); ok {
		out["effective"] = a.Engine.Effective(id).Effective()
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) knownList(id string) bool {
	l, ok := a.Lists.Find(id)
	return ok && l.Owner == ""
}

// assignCustomIDs gives user lists stable ids namespaced per user ("u<uid>_<random>").
func assignCustomIDs(in []policy.CustomList, prefix string, old []policy.CustomList) []policy.CustomList {
	byURL := map[string]string{}
	for _, c := range old {
		byURL[c.URL] = c.ID
	}
	out := make([]policy.CustomList, 0, len(in))
	for _, c := range in {
		c.URL = strings.TrimSpace(c.URL)
		if !strings.HasPrefix(c.ID, prefix) {
			c.ID = ""
		}
		if id, ok := byURL[c.URL]; ok {
			c.ID = id
		}
		if c.ID == "" {
			c.ID = prefix + store.RandomToken(4)
		}
		out = append(out, c)
	}
	return out
}

// savePolicy validates and stores a policy for a scope. Network categories that are switched off
// also switch off the network's lists of that category.
func (a *API) savePolicy(scope string, p policy.Policy) (policy.Policy, error) {
	old := a.scopePolicy(scope)
	switch {
	case scope == "default":
		p.Lists, p.CustomLists = []string{}, nil
	case strings.HasPrefix(scope, "user:"):
		p.CustomLists = assignCustomIDs(p.CustomLists, "u"+strings.TrimPrefix(scope, "user:")+"_", old.CustomLists)
	default:
		p.CustomLists = nil
	}
	if err := p.Normalize(a.knownList, !strings.HasPrefix(scope, "user:")); err != nil {
		return p, err
	}
	p.UpdatedAt = time.Now().UnixMilli()
	key := dnsserver.NetworkPolicyKey
	if scope != "default" {
		key = "policy:" + scope
	}
	if err := a.Store.PutJSON(key, p); err != nil {
		return p, err
	}
	if scope == "default" {
		st := a.Engine.Settings()
		var keep []string
		for _, id := range st.EnabledLists {
			l, ok := a.Lists.Find(id)
			if ok && slices.Contains(old.Categories, l.Category) && !slices.Contains(p.Categories, l.Category) {
				continue // category switched off: its lists go too
			}
			keep = append(keep, id)
		}
		if len(keep) != len(st.EnabledLists) {
			st.EnabledLists = keep
			if err := a.Store.PutSettings(st); err != nil {
				return p, err
			}
			_ = a.Engine.Reload(st)
		}
	}
	a.reload()
	return p, nil
}

func (a *API) putPolicy(w http.ResponseWriter, r *http.Request) {
	scope, ok := a.policyScope(r, true)
	if !ok {
		fail(w, http.StatusForbidden, "not allowed")
		return
	}
	var p policy.Policy
	if err := readJSON(r, &p); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	saved, err := a.savePolicy(scope, p)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scope": scope, "policy": saved})
}

// ───────────────────────── local records ─────────────────────────

func (a *API) getRewrites(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.Engine.Rewrites())
}

func (a *API) addRewrite(w http.ResponseWriter, r *http.Request) {
	var rw policy.Rewrite
	if err := readJSON(r, &rw); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := rw.Validate(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	all := a.Engine.Rewrites()
	if len(all) >= 5000 {
		fail(w, http.StatusBadRequest, "too many local records")
		return
	}
	for _, x := range all {
		if x.Domain == rw.Domain && x.Type == rw.Type && x.Value == rw.Value {
			fail(w, http.StatusConflict, "that record already exists")
			return
		}
	}
	rw.ID = store.RandomToken(5)
	all = append(all, rw)
	if err := a.Store.PutJSON(dnsserver.RewritesKey, all); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reload()
	writeJSON(w, http.StatusCreated, rw)
}

func (a *API) deleteRewrite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	all := a.Engine.Rewrites()
	out := all[:0]
	for _, x := range all {
		if x.ID != id {
			out = append(out, x)
		}
	}
	if err := a.Store.PutJSON(dnsserver.RewritesKey, out); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reload()
	w.WriteHeader(http.StatusNoContent)
}

// ───────────────────────── discovered clients ─────────────────────────

type clientView struct {
	store.Client
	DeviceID   string `json:"deviceId,omitempty"`
	DeviceName string `json:"deviceName,omitempty"`
	LAN        bool   `json:"lan"`
}

func (a *API) getClients(w http.ResponseWriter, r *http.Request) {
	a.Clients.Flush(time.Now().Unix())
	cs, err := a.Store.Clients(1000)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	devs, _ := a.Store.Devices(nil)
	names := map[string]string{}
	for _, d := range devs {
		names[d.ID] = d.Name
	}
	out := make([]clientView, 0, len(cs))
	for _, c := range cs {
		v := clientView{Client: c, DeviceID: a.Engine.DeviceForIP(c.IP), LAN: netinfo.IsLANString(c.IP)}
		v.DeviceName = names[v.DeviceID]
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// nameClient creates a LAN device for a discovered address, or adds the address to an existing device.
func (a *API) nameClient(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IP       string `json:"ip"`
		Name     string `json:"name"`
		DeviceID string `json:"deviceId"`
	}
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	ip, ok := netinfo.Parse(b.IP)
	if !ok {
		fail(w, http.StatusBadRequest, "not an IP address")
		return
	}
	if b.DeviceID != "" {
		d, err := a.Store.Device(b.DeviceID)
		if err != nil {
			fail(w, http.StatusNotFound, "device not found")
			return
		}
		if !slices.Contains(d.IPs, ip.String()) {
			d.IPs = append(d.IPs, ip.String())
		}
		if err := a.Store.UpdateDevice(d); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.reload()
		writeJSON(w, http.StatusOK, a.view(d))
		return
	}
	name := strings.TrimSpace(b.Name)
	if name == "" {
		name = fmt.Sprintf("Device %s", ip)
	}
	u := userOf(r)
	d, err := a.Store.CreateDevice(&u.ID, name, "lan", []string{ip.String()})
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reload()
	writeJSON(w, http.StatusCreated, a.view(d))
}
