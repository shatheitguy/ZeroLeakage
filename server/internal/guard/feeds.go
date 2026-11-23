package guard

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/netinfo"
)

// Feed is a public threat-IP list that needs no account. DNS feeds are conservative (hijacked netblocks,
// botnet C2) and are safe for filtering DNS answers; the others list attackers (scanners, brute-forcers)
// and are meant for firewalls via the bouncer export.
type Feed struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
	DNS         bool   `json:"dnsDefault"`
	Homepage    string `json:"homepage"`
}

// Feeds is the catalog (each URL verified to be reachable; Spamhaus EDROP is now merged into DROP).
// Order is the feed's bit in a range mask: append only.
var Feeds = []Feed{
	{"spamhaus_drop", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", "Hijacked and criminal-controlled netblocks (EDROP is merged into it).", true, "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"},
	{"spamhaus_dropv6", "Spamhaus DROPv6", "https://www.spamhaus.org/drop/dropv6.txt", "The IPv6 version of DROP.", true, "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"},
	{"firehol_level1", "FireHOL Level 1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "Curated for blocking with minimal false positives (DROP, C2, ransomware).", true, "https://iplists.firehol.org/?ipset=firehol_level1"},
	{"feodo", "abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "Botnet command-and-control servers (Dridex, Emotet, QakBot…).", true, "https://feodotracker.abuse.ch/"},
	{"et_compromised", "Emerging Threats compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "Known compromised hosts.", false, "https://rules.emergingthreats.net/"},
	{"blocklist_de", "blocklist.de (all)", "https://lists.blocklist.de/lists/all.txt", "Hosts reported for SSH, mail, web and FTP attacks in the last 48 hours.", false, "https://www.blocklist.de/"},
	{"cins", "CINS Army", "https://cinsscore.com/list/ci-badguys.txt", "Hosts with a poor Sentinel IPS reputation.", false, "https://cinsscore.com/"},
}

// FeedIndex returns the bit of a feed id (-1 when unknown).
func FeedIndex(id string) int {
	for i, f := range Feeds {
		if f.ID == id {
			return i
		}
	}
	return -1
}

func feedMask(ids []string) uint32 {
	var m uint32
	for _, id := range ids {
		if i := FeedIndex(id); i >= 0 {
			m |= 1 << i
		}
	}
	return m
}

// FeedNames lists the names of the feeds in mask.
func FeedNames(mask uint32) []string {
	var out []string
	for i, f := range Feeds {
		if mask&(1<<i) != 0 {
			out = append(out, f.Name)
		}
	}
	return out
}

// ParseFeed reads IPs and CIDRs (one per line; '#' and ';' start comments, extra columns are ignored).
// Private, reserved and absurdly wide entries are dropped: they would only cause false positives.
func ParseFeed(r io.Reader) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		p, ok := netinfo.ParsePrefix(f[0])
		if !ok {
			continue
		}
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
			continue
		}
		lo, hi := span(p)
		v4 := p.Addr().Is4()
		if netinfo.IsSpecial(lo.addr(v4)) || netinfo.IsSpecial(hi.addr(v4)) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// FeedStatus is the state of one feed on this server.
type FeedStatus struct {
	Entries   int       `json:"entries"`
	UpdatedAt time.Time `json:"updatedAt"`
	Error     string    `json:"error,omitempty"`
}

func (g *Guard) feedPath(id string) string { return filepath.Join(g.dir, id+".txt") }

// RefreshFeeds (re)builds the threat set from the feeds in use, downloading those older than maxAge
// (0 = only missing ones). Feeds that are switched off are neither downloaded nor loaded.
func (g *Guard) RefreshFeeds(ctx context.Context, maxAge time.Duration) {
	g.feedMu.Lock()
	defer g.feedMu.Unlock()
	cfg := g.Config()
	want := feedMask(cfg.DNSFeeds) | feedMask(cfg.ExportFeeds)
	if !cfg.Enabled {
		want = 0
	}
	b := &Builder{}
	status := map[string]FeedStatus{}
	for i, f := range Feeds {
		if want&(1<<i) == 0 {
			continue
		}
		data, mod, err := g.loadFeed(ctx, f, maxAge)
		st := FeedStatus{UpdatedAt: mod}
		if err != nil {
			st.Error = err.Error()
			g.Log.Warn("guard feed unavailable", "feed", f.ID, "err", err)
		}
		if len(data) > 0 {
			ps := ParseFeed(strings.NewReader(string(data)))
			for _, p := range ps {
				b.Add(p, i)
			}
			st.Entries = len(ps)
		}
		status[f.ID] = st
	}
	set := b.Build()
	g.set.Store(set)
	g.mu.Lock()
	g.feedStatus = status
	g.mu.Unlock()
	g.Log.Info("guard threat set rebuilt", "feeds", len(status), "ranges", set.Len())
}

func (g *Guard) loadFeed(ctx context.Context, f Feed, maxAge time.Duration) ([]byte, time.Time, error) {
	path := g.feedPath(f.ID)
	fi, statErr := os.Stat(path)
	if statErr == nil && (maxAge == 0 || time.Since(fi.ModTime()) < maxAge) {
		data, err := os.ReadFile(path)
		return data, fi.ModTime(), err
	}
	data, err := g.download(ctx, f.URL)
	if err != nil {
		if statErr == nil {
			old, _ := os.ReadFile(path)
			return old, fi.ModTime(), fmt.Errorf("update failed, using cached copy: %w", err)
		}
		return nil, time.Time{}, err
	}
	_ = os.MkdirAll(g.dir, 0o755)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err == nil {
		_ = os.Rename(tmp, path)
	}
	return data, time.Now(), nil
}

func (g *Guard) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ZeroLeakage-Server")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}
