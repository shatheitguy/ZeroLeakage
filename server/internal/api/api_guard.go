package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/guard"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
)

func (a *API) guardOff(w http.ResponseWriter) bool {
	if a.Guard == nil {
		fail(w, http.StatusServiceUnavailable, "Guard is not running")
		return true
	}
	return false
}

type feedView struct {
	guard.Feed
	DNS    bool              `json:"dns"`
	Export bool              `json:"export"`
	Status *guard.FeedStatus `json:"status,omitempty"`
}

func (a *API) guardStatus(w http.ResponseWriter, r *http.Request) {
	if a.guardOff(w) {
		return
	}
	cfg := a.Guard.Config()
	status := a.Guard.FeedStatus()
	feeds := []feedView{}
	for _, f := range guard.Feeds {
		v := feedView{Feed: f, DNS: contains(cfg.DNSFeeds, f.ID), Export: contains(cfg.ExportFeeds, f.ID)}
		if s, ok := status[f.ID]; ok {
			v.Status = &s
		}
		feeds = append(feeds, v)
	}
	alerts, _ := a.Store.Alerts(store.AlertFilter{SinceMs: time.Now().Add(-7 * 24 * time.Hour).UnixMilli(), Limit: 100})
	bouncers, _ := a.Store.Bouncers()
	writeJSON(w, http.StatusOK, map[string]any{
		"config": cfg, "feeds": feeds, "neverBan": a.Guard.NeverBanList(), "bans": a.Guard.ActiveBans(),
		"alerts": alerts, "bouncers": bouncers,
		"stats": map[string]int64{
			"alerts": a.Guard.Stats.Alerts.Load(), "bans": a.Guard.Stats.Bans.Load(),
			"threatAnswers": a.Guard.Stats.ThreatAnswers.Load(), "ranges": int64(a.Guard.ThreatRanges()),
		},
	})
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (a *API) guardConfig(w http.ResponseWriter, r *http.Request) {
	if a.guardOff(w) {
		return
	}
	cfg := a.Guard.Config()
	if err := readJSON(r, &cfg); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	saved, err := a.Guard.SetConfig(cfg)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	go a.Guard.RefreshFeeds(context.Background(), 0)
	writeJSON(w, http.StatusOK, saved)
}

func (a *API) guardBan(w http.ResponseWriter, r *http.Request) {
	if a.guardOff(w) {
		return
	}
	var b struct {
		IP      string `json:"ip"`
		Minutes int    `json:"minutes"`
		Reason  string `json:"reason"`
	}
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	reason := strings.TrimSpace(b.Reason)
	if reason == "" {
		reason = "Banned by " + userOf(r).Username
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	d, err := a.Guard.Ban(b.IP, guard.ScenarioManual, reason, "manual", b.Minutes)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	a.Guard.RecordAlert(store.Alert{IP: d.IP, Scenario: guard.ScenarioManual, Message: reason, Action: "ban"})
	writeJSON(w, http.StatusCreated, d)
}

func (a *API) guardUnban(w http.ResponseWriter, r *http.Request) {
	if a.guardOff(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := a.Guard.Unban(id); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) guardUnbanIP(w http.ResponseWriter, r *http.Request) {
	if a.guardOff(w) {
		return
	}
	var b struct {
		IP string `json:"ip"`
	}
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := a.Guard.UnbanIP(b.IP); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) guardRefresh(w http.ResponseWriter, r *http.Request) {
	if a.guardOff(w) {
		return
	}
	go a.Guard.RefreshFeeds(context.Background(), time.Minute)
	writeJSON(w, http.StatusAccepted, map[string]bool{"refreshing": true})
}

func (a *API) guardAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hours, _ := strconv.Atoi(q.Get("hours"))
	if hours <= 0 || hours > 24*90 {
		hours = 24 * 7
	}
	as, err := a.Store.Alerts(store.AlertFilter{SinceMs: time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli(), IP: q.Get("ip"), DeviceID: q.Get("device"), Limit: 500})
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, as)
}

func (a *API) getBouncers(w http.ResponseWriter, r *http.Request) {
	bs, err := a.Store.Bouncers()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, bs)
}

func (a *API) createBouncer(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &b); err != nil || strings.TrimSpace(b.Name) == "" {
		fail(w, http.StatusBadRequest, "name required")
		return
	}
	name := strings.TrimSpace(b.Name)
	if len(name) > 60 {
		name = name[:60]
	}
	bc, key, err := a.Store.CreateBouncer(name)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"bouncer": bc, "key": key})
}

func (a *API) deleteBouncer(w http.ResponseWriter, r *http.Request) {
	_ = a.Store.DeleteBouncer(r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// blocklist serves the plain IP/CIDR list for firewalls. Accepted credentials: a bouncer key
// (X-Api-Key header, "Authorization: Bearer", or ?key= for firewalls that can only fetch a URL),
// a linked app's device token, or an admin dashboard session.
func (a *API) blocklist(w http.ResponseWriter, r *http.Request) {
	if a.Guard == nil {
		http.Error(w, "Guard is not running", http.StatusServiceUnavailable)
		return
	}
	ip := a.clientIP(r)
	ok := false
	for _, key := range []string{r.Header.Get("X-Api-Key"), bearer(r), r.URL.Query().Get("key")} {
		if key == "" {
			continue
		}
		if strings.HasPrefix(key, "zlb_") {
			if _, err := a.Store.BouncerByKey(key, ip); err == nil {
				ok = true
			}
		} else if _, err := a.Store.DeviceByToken(key); err == nil {
			ok = true
		}
		if ok {
			break
		}
	}
	if !ok {
		if c, err := r.Cookie(sessionCookie); err == nil {
			if u, err := a.Store.SessionUser(c.Value); err == nil && u.IsAdmin {
				ok = true
			}
		}
	}
	if !ok {
		if a.authBlocked(ip) {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		a.recordFailure(ip)
		w.Header().Set("WWW-Authenticate", `Bearer realm="zeroleakage-guard"`)
		http.Error(w, "bouncer key or device token required", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	o := guard.ExportOptions{Feeds: q.Get("feeds") != "0", Bans: q.Get("bans") != "0"}
	switch q.Get("family") {
	case "4", "ipv4":
		o.Family = 4
	case "6", "ipv6":
		o.Family = 6
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = a.Guard.WriteBlocklist(w, o)
}
