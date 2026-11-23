// Package lists holds the filter-list catalog, downloads and caches lists, and builds the rule index.
package lists

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/filter"
	"github.com/shatheitguy/ZeroLeakage/server/internal/netinfo"
)

//go:embed builtin/*.txt
var builtin embed.FS

// List is one catalog entry (or a custom list added by URL).
type List struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Group       string `json:"group"`
	Category    string `json:"category"` // category id (see Categories)
	URL         string `json:"url,omitempty"`
	Builtin     string `json:"-"`
	Homepage    string `json:"homepage,omitempty"`
	DefaultOn   bool   `json:"defaultOn"`
	// Restricted lists were added by a non-admin user: they are only fetched over https from public
	// addresses, so nobody can make the server request something on the LAN.
	Restricted bool   `json:"-"`
	Owner      string `json:"owner,omitempty"` // "user:<id>" for lists a user added to their own policy
	Custom     bool   `json:"custom"`
}

const (
	hagezi = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock"
	sb     = "https://raw.githubusercontent.com/StevenBlack/hosts/master"
)

// Catalog mirrors the ZeroLeakage Android app so both behave the same.
var Catalog = []List{
	{ID: "telemetry", Name: "OS & OEM Telemetry", Description: "Google, Samsung, Xiaomi, Huawei & Meta phone-home endpoints.", Group: "Built-in", Category: "telemetry", Builtin: "blocklist_telemetry.txt", DefaultOn: true},
	{ID: "trackers", Name: "Ad & Tracker Mesh", Description: "Ad networks, attribution SDKs, pixels and fingerprinting.", Group: "Built-in", Category: "ads", Builtin: "blocklist_trackers.txt", DefaultOn: true},
	{ID: "analytics", Name: "App Analytics SDKs", Description: "Crash reporters and product analytics.", Group: "Built-in", Category: "ads", Builtin: "blocklist_analytics.txt", DefaultOn: true},
	{ID: "malware", Name: "Malware & Phishing (core)", Description: "Known stalkerware, cryptojacking and phishing hosts.", Group: "Built-in", Category: "malware", Builtin: "blocklist_malware.txt", DefaultOn: true},

	{ID: "adguard_dns", Name: "AdGuard DNS filter", Description: "AdGuard's DNS-optimised list: ads, trackers and analytics.", Group: "Ads & trackers", Category: "ads", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Homepage: "https://github.com/AdguardTeam/AdGuardSDNSFilter", DefaultOn: true},
	{ID: "adaway", Name: "AdAway default", Description: "Classic mobile ad-server hosts file.", Group: "Ads & trackers", Category: "ads", URL: "https://adaway.org/hosts.txt", Homepage: "https://adaway.org"},
	{ID: "pgl", Name: "Peter Lowe's list", Description: "Hand-curated ad and tracking servers.", Group: "Ads & trackers", Category: "ads", URL: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", Homepage: "https://pgl.yoyo.org/adservers/"},
	{ID: "easyprivacy", Name: "EasyPrivacy", Description: "Tracking-only list (domain rules only).", Group: "Ads & trackers", Category: "ads", URL: "https://easylist.to/easylist/easyprivacy.txt", Homepage: "https://easylist.to", DefaultOn: true},
	{ID: "hagezi_popup", Name: "HaGeZi Pop-Up Ads", Description: "Malicious pop-up and redirect ad networks.", Group: "Ads & trackers", Category: "ads", URL: hagezi + "/popupads.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "someonewhocares", Name: "Dan Pollock's hosts", Description: "Ads, banners, tracking and shock sites.", Group: "Ads & trackers", Category: "ads", URL: "https://someonewhocares.org/hosts/zero/hosts", Homepage: "https://someonewhocares.org/hosts/"},

	{ID: "oisd_small", Name: "OISD Small", Description: "Ads, trackers and malware with almost zero breakage.", Group: "All-in-one", Category: "ads", URL: "https://small.oisd.nl/", Homepage: "https://oisd.nl"},
	{ID: "oisd_big", Name: "OISD Big", Description: "OISD's full list, tuned for no false positives.", Group: "All-in-one", Category: "ads", URL: "https://big.oisd.nl/", Homepage: "https://oisd.nl"},
	{ID: "hagezi_light", Name: "HaGeZi Light", Description: "Basic protection: ads, tracking, metrics.", Group: "All-in-one", Category: "ads", URL: hagezi + "/light.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "hagezi_multi", Name: "HaGeZi Multi Normal", Description: "Ads, affiliate, tracking, telemetry, phishing, malware.", Group: "All-in-one", Category: "ads", URL: hagezi + "/multi.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "hagezi_pro", Name: "HaGeZi Multi PRO", Description: "Extended protection, recommended by HaGeZi.", Group: "All-in-one", Category: "ads", URL: hagezi + "/pro.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "stevenblack", Name: "StevenBlack Unified hosts", Description: "Consolidated hosts from AdAway, Dan Pollock, URLhaus and more.", Group: "All-in-one", Category: "ads", URL: sb + "/hosts", Homepage: "https://github.com/StevenBlack/hosts"},

	{ID: "hagezi_xiaomi", Name: "Native tracker: Xiaomi", Description: "MIUI / HyperOS analytics.", Group: "Device telemetry", Category: "telemetry", URL: hagezi + "/native.xiaomi.txt"},
	{ID: "hagezi_samsung", Name: "Native tracker: Samsung", Description: "One UI analytics.", Group: "Device telemetry", Category: "telemetry", URL: hagezi + "/native.samsung.txt"},
	{ID: "hagezi_huawei", Name: "Native tracker: Huawei", Description: "EMUI / HarmonyOS analytics.", Group: "Device telemetry", Category: "telemetry", URL: hagezi + "/native.huawei.txt"},
	{ID: "hagezi_winoffice", Name: "Native tracker: Windows / Office", Description: "Windows and Office telemetry.", Group: "Device telemetry", Category: "telemetry", URL: hagezi + "/native.winoffice.txt"},
	{ID: "hagezi_tiktok", Name: "Native tracker: TikTok", Description: "TikTok analytics and fingerprinting.", Group: "Device telemetry", Category: "telemetry", URL: hagezi + "/native.tiktok.txt"},
	{ID: "hagezi_amazon", Name: "Native tracker: Amazon", Description: "Amazon device and app metrics.", Group: "Device telemetry", Category: "telemetry", URL: hagezi + "/native.amazon.txt"},
	{ID: "hagezi_apple", Name: "Native tracker: Apple", Description: "Apple analytics endpoints.", Group: "Device telemetry", Category: "telemetry", URL: hagezi + "/native.apple.txt"},
	{ID: "hagezi_lgwebos", Name: "Native tracker: LG webOS", Description: "Smart-TV telemetry from LG.", Group: "Device telemetry", Category: "telemetry", URL: hagezi + "/native.lgwebos.txt"},

	{ID: "hagezi_tif_mini", Name: "HaGeZi Threat Intelligence (mini)", Description: "Malware, phishing, scam and C2 domains.", Group: "Security", Category: "malware", URL: hagezi + "/tif.mini.txt"},
	{ID: "urlhaus", Name: "URLhaus malware filter", Description: "Malware distribution hosts from abuse.ch.", Group: "Security", Category: "malware", URL: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt"},
	{ID: "phishing_army", Name: "Phishing Army", Description: "Phishing domains from PhishTank, OpenPhish and others.", Group: "Security", Category: "malware", URL: "https://phishing.army/download/phishing_army_blocklist.txt"},
	{ID: "nocoin", Name: "NoCoin", Description: "Browser crypto-mining.", Group: "Security", Category: "cryptomining", URL: "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"},

	{ID: "sb_gambling", Name: "Gambling", Description: "Betting and casino sites.", Group: "Parental", Category: "gambling", URL: sb + "/alternates/gambling-only/hosts"},
	{ID: "sb_adult", Name: "Adult content", Description: "Pornography sites.", Group: "Parental", Category: "adult", URL: sb + "/alternates/porn-only/hosts"},
	{ID: "sb_social", Name: "Social media", Description: "Facebook, Instagram, TikTok, X and other social networks.", Group: "Parental", Category: "social", URL: sb + "/alternates/social-only/hosts"},
	{ID: "hagezi_nsfw", Name: "HaGeZi NSFW", Description: "Adult content, including subdomains.", Group: "Parental", Category: "adult", URL: hagezi + "/nsfw.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "hagezi_gambling", Name: "HaGeZi Gambling", Description: "Betting, casinos and lotteries (medium).", Group: "Parental", Category: "gambling", URL: hagezi + "/gambling.medium.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "sb_fakenews", Name: "Fake news", Description: "Sites known for publishing disinformation (StevenBlack).", Group: "Parental", Category: "fakenews", URL: sb + "/alternates/fakenews-only/hosts"},
	{ID: "hagezi_piracy", Name: "HaGeZi Anti-Piracy", Description: "Sites mainly used to distribute copyrighted content illegally.", Group: "Parental", Category: "piracy", URL: hagezi + "/anti.piracy.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "hagezi_fake", Name: "HaGeZi Fake", Description: "Scam shops, fake stores and other internet traps.", Group: "Security", Category: "malware", URL: hagezi + "/fake.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{ID: "hagezi_doh", Name: "HaGeZi DoH/VPN/Proxy bypass", Description: "Encrypted DNS, VPN, Tor and proxy services used to get around filtering.", Group: "Security", Category: "bypass", URL: hagezi + "/doh-vpn-proxy-bypass.txt", Homepage: "https://github.com/hagezi/dns-blocklists"},
}

// Category groups lists into a web category that a policy can switch on or off (Zenarmor-style).
type Category struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	AutoLists   []string `json:"autoLists"` // lists used when no list of this category is enabled
	DefaultOn   bool     `json:"defaultOn"`
}

// Categories in display order. Privacy and security categories are on by default.
var Categories = []Category{
	{ID: "ads", Name: "Ads & trackers", Description: "Ad networks, trackers, analytics SDKs and attribution.", AutoLists: []string{"trackers", "analytics"}, DefaultOn: true},
	{ID: "telemetry", Name: "Telemetry", Description: "OS, OEM, smart-TV and app phone-home endpoints.", AutoLists: []string{"telemetry"}, DefaultOn: true},
	{ID: "malware", Name: "Malware & phishing", Description: "Malware, phishing, scam and command-and-control domains.", AutoLists: []string{"malware", "hagezi_tif_mini"}, DefaultOn: true},
	{ID: "cryptomining", Name: "Crypto-mining", Description: "Browser and app crypto-jacking.", AutoLists: []string{"nocoin"}, DefaultOn: true},
	{ID: "adult", Name: "Adult content", Description: "Pornography and explicit sites.", AutoLists: []string{"hagezi_nsfw"}},
	{ID: "gambling", Name: "Gambling", Description: "Betting, casinos and lotteries.", AutoLists: []string{"hagezi_gambling"}},
	{ID: "social", Name: "Social networks", Description: "Facebook, Instagram, TikTok, X and other social networks.", AutoLists: []string{"sb_social"}},
	{ID: "fakenews", Name: "Fake news", Description: "Sites known for publishing disinformation.", AutoLists: []string{"sb_fakenews"}},
	{ID: "piracy", Name: "Piracy & torrents", Description: "Sites mainly used to share copyrighted content illegally.", AutoLists: []string{"hagezi_piracy"}},
	{ID: "bypass", Name: "VPN, proxy & DNS bypass", Description: "Encrypted DNS, VPN, Tor and proxy services that get around filtering.", AutoLists: []string{"hagezi_doh"}},
	{ID: "custom", Name: "Custom lists", Description: "Lists added by URL.", DefaultOn: true},
}

// FindCategory returns a category by id.
func FindCategory(id string) (Category, bool) {
	for _, c := range Categories {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// CategoryName is the display name for a category id ("Custom lists" for unknown ids).
func CategoryName(id string) string {
	if c, ok := FindCategory(id); ok {
		return c.Name
	}
	return "Custom lists"
}

// NormalizeCategory maps legacy or unknown values to a known category id.
func NormalizeCategory(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if _, ok := FindCategory(v); ok {
		return v
	}
	return "custom"
}

// DefaultCategories are the categories the network policy blocks out of the box.
func DefaultCategories() []string {
	var ids []string
	for _, c := range Categories {
		if c.DefaultOn {
			ids = append(ids, c.ID)
		}
	}
	return ids
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

// ForCategories returns the extra lists needed so that every category in cats is covered: a category
// that already has one of `have` (enabled lists) is left alone, otherwise its curated AutoLists are used.
func ForCategories(cats []string, have []string, all []List) []string {
	catOf := map[string]string{}
	for _, l := range all {
		catOf[l.ID] = l.Category
	}
	covered := map[string]bool{}
	for _, id := range have {
		covered[catOf[id]] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range cats {
		if covered[c] {
			continue
		}
		cat, ok := FindCategory(c)
		if !ok {
			continue
		}
		for _, id := range cat.AutoLists {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
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
	dir        string
	client     *http.Client
	restricted *http.Client // for lists added by non-admin users: public https only
	log        *slog.Logger

	mu      sync.Mutex
	custom  []List
	status  map[string]Status
	index   atomic.Pointer[filter.Index]
	buildMu sync.Mutex
	OnBuild func(*filter.Index) // called after every rebuild (e.g. to clear the DNS cache)
}

func NewManager(dataDir string, log *slog.Logger) *Manager {
	m := &Manager{
		dir:        filepath.Join(dataDir, "lists"),
		client:     &http.Client{Timeout: 60 * time.Second},
		restricted: PublicOnlyClient(60 * time.Second),
		log:        log,
		status:     map[string]Status{},
	}
	m.index.Store(filter.Empty)
	_ = os.MkdirAll(m.dir, 0o755)
	return m
}

// PublicOnlyClient refuses to connect to private, loopback or otherwise local addresses (SSRF guard).
func PublicOnlyClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		a, ok := netinfo.Parse(host)
		if !ok || netinfo.IsSpecial(a) {
			return fmt.Errorf("refusing to fetch from local address %s", host)
		}
		return nil
	}}
	tr := &http.Transport{Proxy: nil, DialContext: d.DialContext, TLSHandshakeTimeout: 10 * time.Second, MaxIdleConns: 4}
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 5 {
			return fmt.Errorf("redirect not allowed")
		}
		return nil
	}}
}

// Index is the live rule index (never nil).
func (m *Manager) Index() *filter.Index { return m.index.Load() }

// SetCustom replaces the custom lists (admin lists from the store plus lists users added to their policy).
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

// Find returns a catalog or custom list by id.
func (m *Manager) Find(id string) (List, bool) {
	for _, l := range m.All() {
		if l.ID == id {
			return l, true
		}
	}
	return List{}, false
}

func (m *Manager) cachePath(id string) string { return filepath.Join(m.dir, id+".txt") }

// Rebuild builds a new index from the given lists, downloading any that are missing
// or older than maxAge (0 = only download missing ones). Concurrent calls are serialised.
func (m *Manager) Rebuild(ctx context.Context, enabled []string, maxAge time.Duration) {
	m.buildMu.Lock()
	defer m.buildMu.Unlock()
	b := filter.NewBuilder()
	seen := map[string]bool{}
	for _, id := range enabled {
		if seen[id] {
			continue
		}
		seen[id] = true
		l, ok := m.Find(id)
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
			src := filter.Source{ID: l.ID, Name: l.Name, Category: CategoryName(l.Category), CategoryID: NormalizeCategory(l.Category)}
			if n := b.AddList(src, bytes.NewReader(data), l.Builtin != ""); n < 0 {
				st.Error = fmt.Sprintf("too many lists in use (max %d)", filter.MaxSources)
			} else {
				st.Rules = n
			}
		}
		m.mu.Lock()
		m.status[l.ID] = st
		m.mu.Unlock()
	}
	idx := b.Build()
	m.index.Store(idx)
	if m.OnBuild != nil {
		m.OnBuild(idx)
	}
	m.log.Info("filter index rebuilt", "lists", len(seen), "rules", idx.TotalRules())
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
	data, err := m.download(ctx, l)
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

func (m *Manager) download(ctx context.Context, l List) ([]byte, error) {
	url := l.URL
	client := m.client
	if l.Restricted {
		client = m.restricted
		if !strings.HasPrefix(url, "https://") {
			return nil, fmt.Errorf("user lists must use https")
		}
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return nil, fmt.Errorf("invalid list URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ZeroLeakage-Server")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
