// Package lists holds the filter-list catalog, downloads and caches lists, and builds the rule index.
package lists

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/filter"
)

//go:embed builtin/*.txt
var builtin embed.FS

// List is one catalog entry (or a custom list added by URL).
type List struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Group       string `json:"group"`
	Category    string `json:"category"`
	URL         string `json:"url,omitempty"`
	Builtin     string `json:"-"`
	Homepage    string `json:"homepage,omitempty"`
	DefaultOn   bool   `json:"defaultOn"`
	Custom      bool   `json:"custom"`
}

const (
	hagezi = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock"
	sb     = "https://raw.githubusercontent.com/StevenBlack/hosts/master"
)

// Catalog mirrors the ZeroLeakage Android app so both behave the same.
var Catalog = []List{
	{ID: "telemetry", Name: "OS & OEM Telemetry", Description: "Google, Samsung, Xiaomi, Huawei & Meta phone-home endpoints.", Group: "Built-in", Category: "Telemetry", Builtin: "blocklist_telemetry.txt", DefaultOn: true},
	{ID: "trackers", Name: "Ad & Tracker Mesh", Description: "Ad networks, attribution SDKs, pixels and fingerprinting.", Group: "Built-in", Category: "Ad Tracker", Builtin: "blocklist_trackers.txt", DefaultOn: true},
	{ID: "analytics", Name: "App Analytics SDKs", Description: "Crash reporters and product analytics.", Group: "Built-in", Category: "Analytics", Builtin: "blocklist_analytics.txt", DefaultOn: true},
	{ID: "malware", Name: "Malware & Phishing (core)", Description: "Known stalkerware, cryptojacking and phishing hosts.", Group: "Built-in", Category: "Malware", Builtin: "blocklist_malware.txt", DefaultOn: true},

	{ID: "adguard_dns", Name: "AdGuard DNS filter", Description: "AdGuard's DNS-optimised list: ads, trackers and analytics.", Group: "Ads & trackers", Category: "Ad Tracker", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Homepage: "https://github.com/AdguardTeam/AdGuardSDNSFilter", DefaultOn: true},
	{ID: "adaway", Name: "AdAway default", Description: "Classic mobile ad-server hosts file.", Group: "Ads & trackers", Category: "Ad Tracker", URL: "https://adaway.org/hosts.txt", Homepage: "https://adaway.org"},
	{ID: "pgl", Name: "Peter Lowe's list", Description: "Hand-curated ad and tracking servers.", Group: "Ads & trackers", Category: "Ad Tracker", URL: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", Homepage: "https://pgl.yoyo.org/adservers/"},
	{ID: "easyprivacy", Name: "EasyPrivacy", Description: "Tracking-only list (domain rules only).", Group: "Ads & trackers", Category: "Ad Tracker", URL: "https://easylist.to/easylist/easyprivacy.txt", Homepage: "https://easylist.to"},
	{ID: "hagezi_popup", Name: "HaGeZi Pop-Up Ads", Description: "Malicious pop-up and redirect ad networks.", Group: "Ads & trackers", Category: "Ad Tracker", URL: hagezi + "/popupads.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "someonewhocares", Name: "Dan Pollock's hosts", Description: "Ads, banners, tracking and shock sites.", Group: "Ads & trackers", Category: "Ad Tracker", URL: "https://someonewhocares.org/hosts/zero/hosts", Homepage: "https://someonewhocares.org/hosts/"},

	{ID: "oisd_small", Name: "OISD Small", Description: "Ads, trackers and malware with almost zero breakage.", Group: "All-in-one", Category: "Ad Tracker", URL: "https://small.oisd.nl/", Homepage: "https://oisd.nl"},
	{ID: "oisd_big", Name: "OISD Big", Description: "OISD's full list, tuned for no false positives.", Group: "All-in-one", Category: "Ad Tracker", URL: "https://big.oisd.nl/", Homepage: "https://oisd.nl"},
	{ID: "hagezi_light", Name: "HaGeZi Light", Description: "Basic protection: ads, tracking, metrics.", Group: "All-in-one", Category: "Ad Tracker", URL: hagezi + "/light.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "hagezi_multi", Name: "HaGeZi Multi Normal", Description: "Ads, affiliate, tracking, telemetry, phishing, malware.", Group: "All-in-one", Category: "Ad Tracker", URL: hagezi + "/multi.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "hagezi_pro", Name: "HaGeZi Multi PRO", Description: "Extended protection, recommended by HaGeZi.", Group: "All-in-one", Category: "Ad Tracker", URL: hagezi + "/pro.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "stevenblack", Name: "StevenBlack Unified hosts", Description: "Consolidated hosts from AdAway, Dan Pollock, URLhaus and more.", Group: "All-in-one", Category: "Ad Tracker", URL: sb + "/hosts", Homepage: "https://github.com/StevenBlack/hosts"},

	{ID: "hagezi_xiaomi", Name: "Native tracker: Xiaomi", Description: "MIUI / HyperOS analytics.", Group: "Device telemetry", Category: "Telemetry", URL: hagezi + "/native.xiaomi.txt"},
	{ID: "hagezi_samsung", Name: "Native tracker: Samsung", Description: "One UI analytics.", Group: "Device telemetry", Category: "Telemetry", URL: hagezi + "/native.samsung.txt"},
	{ID: "hagezi_huawei", Name: "Native tracker: Huawei", Description: "EMUI / HarmonyOS analytics.", Group: "Device telemetry", Category: "Telemetry", URL: hagezi + "/native.huawei.txt"},
	{ID: "hagezi_winoffice", Name: "Native tracker: Windows / Office", Description: "Windows and Office telemetry.", Group: "Device telemetry", Category: "Telemetry", URL: hagezi + "/native.winoffice.txt"},
	{ID: "hagezi_tiktok", Name: "Native tracker: TikTok", Description: "TikTok analytics and fingerprinting.", Group: "Device telemetry", Category: "Telemetry", URL: hagezi + "/native.tiktok.txt"},
	{ID: "hagezi_amazon", Name: "Native tracker: Amazon", Description: "Amazon device and app metrics.", Group: "Device telemetry", Category: "Telemetry", URL: hagezi + "/native.amazon.txt"},
	{ID: "hagezi_apple", Name: "Native tracker: Apple", Description: "Apple analytics endpoints.", Group: "Device telemetry", Category: "Telemetry", URL: hagezi + "/native.apple.txt"},
	{ID: "hagezi_lgwebos", Name: "Native tracker: LG webOS", Description: "Smart-TV telemetry from LG.", Group: "Device telemetry", Category: "Telemetry", URL: hagezi + "/native.lgwebos.txt"},

	{ID: "hagezi_tif_mini", Name: "HaGeZi Threat Intelligence (mini)", Description: "Malware, phishing, scam and C2 domains.", Group: "Security", Category: "Malware", URL: hagezi + "/tif.mini.txt"},
	{ID: "urlhaus", Name: "URLhaus malware filter", Description: "Malware distribution hosts from abuse.ch.", Group: "Security", Category: "Malware", URL: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt"},
	{ID: "phishing_army", Name: "Phishing Army", Description: "Phishing domains from PhishTank, OpenPhish and others.", Group: "Security", Category: "Malware", URL: "https://phishing.army/download/phishing_army_blocklist.txt"},
	{ID: "nocoin", Name: "NoCoin", Description: "Browser crypto-mining.", Group: "Security", Category: "Malware", URL: "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"},

	{ID: "sb_gambling", Name: "Gambling", Description: "Betting and casino sites.", Group: "Parental", Category: "Gambling", URL: sb + "/alternates/gambling-only/hosts"},
	{ID: "sb_adult", Name: "Adult content", Description: "Pornography sites.", Group: "Parental", Category: "Adult", URL: sb + "/alternates/porn-only/hosts"},
	{ID: "sb_social", Name: "Social media", Description: "Facebook, Instagram, TikTok, X and other social networks.", Group: "Parental", Category: "Social", URL: sb + "/alternates/social-only/hosts"},
}

// DefaultEnabled returns the ids that are on out of the box.
func DefaultEnabled() []string {
	var ids []string
	for _, l := range Catalog {
		if l.DefaultOn {
			ids = append(ids, l.ID)
		}
	}
	return ids
}

// Status is the state of one list on this server.
type Status struct {
	Rules     int       `json:"rules"`
	UpdatedAt time.Time `json:"updatedAt"`
	Error     string    `json:"error,omitempty"`
	Bytes     int64     `json:"bytes"`
}

// Manager downloads enabled lists into dataDir/lists and serves the current index.
type Manager struct {
	dir    string
	client *http.Client
	log    *slog.Logger

	mu     sync.Mutex
	custom []List
	status map[string]Status
	index  atomic.Pointer[filter.Index]
}

func NewManager(dataDir string, log *slog.Logger) *Manager {
	m := &Manager{
		dir:    filepath.Join(dataDir, "lists"),
		client: &http.Client{Timeout: 60 * time.Second},
		log:    log,
		status: map[string]Status{},
	}
	m.index.Store(filter.Empty)
	_ = os.MkdirAll(m.dir, 0o755)
	return m
}

// Index is the live rule index (never nil).
func (m *Manager) Index() *filter.Index { return m.index.Load() }

// SetCustom replaces the user's custom lists (from the store).
func (m *Manager) SetCustom(custom []List) {
	m.mu.Lock()
	m.custom = custom
	m.mu.Unlock()
}

// All returns catalog + custom lists.
func (m *Manager) All() []List {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]List{}, Catalog...)
	return append(out, m.custom...)
}

func (m *Manager) Status() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Status, len(m.status))
	for k, v := range m.status {
		out[k] = v
	}
	return out
}

func (m *Manager) find(id string) (List, bool) {
	for _, l := range m.All() {
		if l.ID == id {
			return l, true
		}
	}
	return List{}, false
}

func (m *Manager) cachePath(id string) string { return filepath.Join(m.dir, id+".txt") }

// Rebuild builds a new index from the enabled lists, downloading any that are missing
// or older than maxAge (0 = only download missing ones).
func (m *Manager) Rebuild(ctx context.Context, enabled []string, maxAge time.Duration) {
	b := filter.NewBuilder()
	for _, id := range enabled {
		l, ok := m.find(id)
		if !ok {
			continue
		}
		data, err := m.load(ctx, l, maxAge)
		st := Status{UpdatedAt: m.modTime(l), Bytes: int64(len(data))}
		if err != nil {
			st.Error = err.Error()
			m.log.Warn("filter list unavailable", "list", l.ID, "err", err)
		}
		if len(data) > 0 {
			st.Rules = b.AddList(filter.Source{ID: l.ID, Name: l.Name, Category: l.Category}, bytes.NewReader(data), l.Builtin != "")
		}
		m.mu.Lock()
		m.status[l.ID] = st
		m.mu.Unlock()
	}
	idx := b.Build()
	m.index.Store(idx)
	m.log.Info("filter index rebuilt", "lists", len(enabled), "rules", idx.TotalRules())
}

func (m *Manager) modTime(l List) time.Time {
	if l.Builtin != "" {
		return time.Time{}
	}
	if fi, err := os.Stat(m.cachePath(l.ID)); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

func (m *Manager) load(ctx context.Context, l List, maxAge time.Duration) ([]byte, error) {
	if l.Builtin != "" {
		return builtin.ReadFile("builtin/" + l.Builtin)
	}
	path := m.cachePath(l.ID)
	fi, statErr := os.Stat(path)
	fresh := statErr == nil && (maxAge == 0 || time.Since(fi.ModTime()) < maxAge)
	if fresh {
		return os.ReadFile(path)
	}
	data, err := m.download(ctx, l.URL)
	if err != nil {
		if statErr == nil { // keep serving the old copy
			old, _ := os.ReadFile(path)
			return old, fmt.Errorf("update failed, using cached copy: %w", err)
		}
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err == nil {
		_ = os.Rename(tmp, path)
	}
	return data, nil
}

func (m *Manager) download(ctx context.Context, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return nil, fmt.Errorf("invalid list URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ZeroLeakage-Server")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
