// Package guard is ZeroLeakage's local, CrowdSec-like protection engine. Everything runs on the
// server: threat-IP feeds are downloaded (no account, nothing is ever reported back), DNS traffic is
// watched for attack patterns, and offenders are alerted on or banned. Bans can be exported as a plain
// blocklist to firewalls ("bouncers").
package guard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/filter"
	"github.com/shatheitguy/ZeroLeakage/server/internal/netinfo"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
)

// Ban effects.
const (
	EffectQuarantine = "quarantine" // block every lookup except the quarantine allowlist (and the dashboard)
	EffectRefuse     = "refuse"     // answer REFUSED to every query
)

// Scenario ids.
const (
	ScenarioFlood      = "dns_flood"
	ScenarioNXDomain   = "nxdomain_storm"
	ScenarioTunnel     = "dns_tunnel"
	ScenarioMalware    = "infected_device"
	ScenarioBruteForce = "http_bruteforce"
	ScenarioManual     = "manual"
)

// Scenario configures one behaviour detector.
type Scenario struct {
	Enabled    bool   `json:"enabled"`
	Action     string `json:"action"`     // alert | ban
	Threshold  int    `json:"threshold"`  // see each scenario
	WindowSec  int    `json:"windowSec"`  // detection window
	BanMinutes int    `json:"banMinutes"` // ban length when Action is ban (0 = 60)
}

// Config is the Guard configuration (stored as JSON under the "guard" key).
type Config struct {
	Enabled         bool     `json:"enabled"`
	DNSFeeds        []string `json:"dnsFeeds"`        // feeds used to block DNS answers that point at bad IPs
	ExportFeeds     []string `json:"exportFeeds"`     // feeds included in the bouncer blocklist
	BanEffectLAN    string   `json:"banEffectLan"`    // quarantine | refuse
	BanEffectPublic string   `json:"banEffectPublic"` // refuse | quarantine (DoH/DoT clients on the internet)
	NeverBan        []string `json:"neverBan"`        // extra IPs / CIDRs (own addresses and gateways are always included)
	QuarantineAllow []string `json:"quarantineAllow"` // domains that still resolve in quarantine

	Flood      Scenario `json:"flood"`      // Threshold = queries per second, averaged over the window
	NXDomain   Scenario `json:"nxdomain"`   // Threshold = distinct non-existent names in the window
	Tunnel     Scenario `json:"tunnel"`     // Threshold = distinct suspicious subdomains of one parent
	Malware    Scenario `json:"malware"`    // Threshold = malware/phishing lookups in the window
	BruteForce Scenario `json:"bruteForce"` // Threshold = failed dashboard/app sign-ins in the window
}

// DefaultConfig: on, conservative DNS feeds, quarantine on the LAN, alerts for the noisy heuristics.
func DefaultConfig() Config {
	var dns, export []string
	for _, f := range Feeds {
		if f.DNS {
			dns = append(dns, f.ID)
		}
		export = append(export, f.ID)
	}
	return Config{
		Enabled: true, DNSFeeds: dns, ExportFeeds: export,
		BanEffectLAN: EffectQuarantine, BanEffectPublic: EffectRefuse,
		NeverBan: []string{}, QuarantineAllow: []string{},
		Flood:      Scenario{Enabled: true, Action: "ban", Threshold: 100, WindowSec: 10, BanMinutes: 10},
		NXDomain:   Scenario{Enabled: true, Action: "alert", Threshold: 150, WindowSec: 300, BanMinutes: 60},
		Tunnel:     Scenario{Enabled: true, Action: "alert", Threshold: 100, WindowSec: 600, BanMinutes: 60},
		Malware:    Scenario{Enabled: true, Action: "alert", Threshold: 10, WindowSec: 3600, BanMinutes: 60},
		BruteForce: Scenario{Enabled: true, Action: "ban", Threshold: 10, WindowSec: 900, BanMinutes: 60},
	}
}

func fixScenario(s *Scenario, def Scenario) {
	if s.Action != "alert" && s.Action != "ban" {
		s.Action = def.Action
	}
	if s.Threshold <= 0 {
		s.Threshold = def.Threshold
	}
	if s.WindowSec <= 0 || s.WindowSec > 86400 {
		s.WindowSec = def.WindowSec
	}
	if s.BanMinutes <= 0 || s.BanMinutes > 525600 {
		s.BanMinutes = def.BanMinutes
	}
}

// Normalize validates a config, filling defaults.
func (c *Config) Normalize() error {
	def := DefaultConfig()
	if c.BanEffectLAN != EffectRefuse {
		c.BanEffectLAN = EffectQuarantine
	}
	if c.BanEffectPublic != EffectQuarantine {
		c.BanEffectPublic = EffectRefuse
	}
	known := func(in []string) []string {
		out := []string{}
		for _, id := range in {
			if FeedIndex(id) >= 0 {
				out = append(out, id)
			}
		}
		return out
	}
	c.DNSFeeds, c.ExportFeeds = known(c.DNSFeeds), known(c.ExportFeeds)
	var nb []string
	for _, v := range c.NeverBan {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := netinfo.ParsePrefix(v); !ok {
			return fmt.Errorf("never-ban entry %q is not an IP or CIDR", v)
		}
		nb = append(nb, v)
	}
	c.NeverBan = nb
	if c.NeverBan == nil {
		c.NeverBan = []string{}
	}
	var qa []string
	for _, d := range c.QuarantineAllow {
		if v, ok := filter.CleanDomain(strings.TrimPrefix(strings.TrimSpace(d), "*.")); ok {
			qa = append(qa, v)
		}
	}
	c.QuarantineAllow = qa
	if c.QuarantineAllow == nil {
		c.QuarantineAllow = []string{}
	}
	fixScenario(&c.Flood, def.Flood)
	fixScenario(&c.NXDomain, def.NXDomain)
	fixScenario(&c.Tunnel, def.Tunnel)
	fixScenario(&c.Malware, def.Malware)
	fixScenario(&c.BruteForce, def.BruteForce)
	return nil
}

// compiled config for the hot path
type runtimeCfg struct {
	Config
	dnsMask, exportMask uint32
	quarantine          map[string]bool
}

type banTable struct {
	exact    map[netip.Addr]store.Decision
	prefixes []prefixBan
}

type prefixBan struct {
	p netip.Prefix
	d store.Decision
}

// Guard is the engine. Create with New, then call Load and Run.
type Guard struct {
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time
	// SelfAddrs / Gateways are overridable for tests.
	SelfAddrs func() []netip.Addr
	Gateways  func() []netip.Addr

	dir    string
	client *http.Client

	cfg   atomic.Pointer[runtimeCfg]
	set   atomic.Pointer[Set]
	bans  atomic.Pointer[banTable]
	never atomic.Pointer[[]netip.Prefix]

	mu         sync.Mutex // decisions, feed status
	decisions  []store.Decision
	feedStatus map[string]FeedStatus
	feedMu     sync.Mutex

	states  sync.Map // ip string -> *clientState
	alertCh chan store.Alert
	Stats   struct{ Alerts, Bans, ThreatAnswers atomic.Int64 }
}

// New creates a Guard storing feeds under dataDir/guard.
func New(st *store.Store, dataDir string, log *slog.Logger) *Guard {
	g := &Guard{
		Store: st, Log: log, Now: time.Now, SelfAddrs: netinfo.SelfAddrs, Gateways: netinfo.Gateways,
		dir:     filepath.Join(dataDir, "guard"),
		client:  &http.Client{Timeout: 60 * time.Second},
		alertCh: make(chan store.Alert, 1024),
	}
	g.set.Store(EmptySet)
	g.bans.Store(&banTable{exact: map[netip.Addr]store.Decision{}})
	empty := []netip.Prefix{}
	g.never.Store(&empty)
	def := DefaultConfig()
	g.apply(def)
	return g
}

// Load reads the configuration and active bans from the store.
func (g *Guard) Load() error {
	cfg := DefaultConfig()
	if _, err := g.Store.GetJSON("guard", &cfg); err != nil {
		return err
	}
	_ = cfg.Normalize()
	g.apply(cfg)
	ds, err := g.Store.ActiveDecisions(g.Now().Unix())
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.decisions = ds
	g.rebuildBansLocked()
	g.mu.Unlock()
	return nil
}

// Config returns the current configuration.
func (g *Guard) Config() Config { return g.cfg.Load().Config }

// SetConfig validates, stores and applies a configuration.
func (g *Guard) SetConfig(c Config) (Config, error) {
	if err := c.Normalize(); err != nil {
		return c, err
	}
	if g.Store != nil {
		if err := g.Store.PutJSON("guard", c); err != nil {
			return c, err
		}
	}
	g.apply(c)
	return c, nil
}

func (g *Guard) apply(c Config) {
	rc := &runtimeCfg{Config: c, dnsMask: feedMask(c.DNSFeeds), exportMask: feedMask(c.ExportFeeds), quarantine: map[string]bool{}}
	for _, d := range c.QuarantineAllow {
		rc.quarantine[d] = true
	}
	g.cfg.Store(rc)
	var never []netip.Prefix
	for _, a := range append(g.SelfAddrs(), g.Gateways()...) {
		if a.IsValid() {
			never = append(never, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	never = append(never, netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"))
	for _, v := range c.NeverBan {
		if p, ok := netinfo.ParsePrefix(v); ok {
			never = append(never, p)
		}
	}
	g.never.Store(&never)
}

// Enabled reports whether Guard is on.
func (g *Guard) Enabled() bool { return g != nil && g.cfg.Load().Enabled }

// NeverBanned reports whether ip is protected from bans (own addresses, gateways, the never-ban list).
func (g *Guard) NeverBanned(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range *g.never.Load() {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// NeverBanList returns the effective never-ban list: automatic entries first.
func (g *Guard) NeverBanList() []string {
	var out []string
	for _, p := range *g.never.Load() {
		if p.IsSingleIP() {
			out = append(out, p.Addr().String())
		} else {
			out = append(out, p.String())
		}
	}
	return out
}

// ThreatIP returns the names of the DNS feeds listing ip (nil when clean or Guard is off).
func (g *Guard) ThreatIP(ip netip.Addr) []string {
	rc := g.cfg.Load()
	if !rc.Enabled || rc.dnsMask == 0 {
		return nil
	}
	ip = ip.Unmap()
	if netinfo.IsSpecial(ip) {
		return nil
	}
	if m := g.set.Load().Lookup(ip) & rc.dnsMask; m != 0 {
		return FeedNames(m)
	}
	return nil
}

// Banned returns the active ban covering ip, or nil.
func (g *Guard) Banned(ip netip.Addr) *store.Decision {
	if g == nil || !g.cfg.Load().Enabled {
		return nil
	}
	t := g.bans.Load()
	if len(t.exact) == 0 && len(t.prefixes) == 0 {
		return nil
	}
	now := g.Now().Unix()
	ip = ip.Unmap()
	if d, ok := t.exact[ip]; ok && (d.ExpiresAt == 0 || d.ExpiresAt > now) {
		return &d
	}
	for i := range t.prefixes {
		pb := &t.prefixes[i]
		if pb.p.Contains(ip) && (pb.d.ExpiresAt == 0 || pb.d.ExpiresAt > now) {
			d := pb.d
			return &d
		}
	}
	return nil
}

// Effect is what a ban does to this client's DNS.
func (g *Guard) Effect(ip netip.Addr) string {
	rc := g.cfg.Load()
	if netinfo.IsLAN(ip) {
		return rc.BanEffectLAN
	}
	return rc.BanEffectPublic
}

// QuarantineAllows reports whether a quarantined client may still resolve domain.
func (g *Guard) QuarantineAllows(domain string, extra ...string) bool {
	rc := g.cfg.Load()
	for _, e := range extra {
		if e != "" && (domain == e || strings.HasSuffix(domain, "."+e)) {
			return true
		}
	}
	if len(rc.quarantine) == 0 {
		return false
	}
	_, ok := filter.Walk(domain, func(s string) bool { return rc.quarantine[s] })
	return ok
}

// ErrNeverBan is returned when banning a protected address.
var ErrNeverBan = errors.New("that address is on the never-ban list (this server, a gateway or your exceptions)")

// Ban adds a decision. minutes <= 0 means "until removed".
func (g *Guard) Ban(target, scenario, reason, origin string, minutes int) (store.Decision, error) {
	p, ok := netinfo.ParsePrefix(target)
	if !ok {
		return store.Decision{}, errors.New("enter an IP address or CIDR")
	}
	if g.NeverBanned(p.Addr()) || (!p.IsSingleIP() && g.overlapsNever(p)) {
		return store.Decision{}, ErrNeverBan
	}
	now := g.Now()
	d := store.Decision{IP: prefixString(p), Scenario: scenario, Reason: reason, Origin: origin, CreatedAt: now.Unix()}
	if minutes > 0 {
		d.ExpiresAt = now.Add(time.Duration(minutes) * time.Minute).Unix()
	}
	if g.Store != nil {
		id, err := g.Store.InsertDecision(d)
		if err != nil {
			return d, err
		}
		d.ID = id
	}
	g.mu.Lock()
	g.decisions = append([]store.Decision{d}, g.decisions...)
	g.rebuildBansLocked()
	g.mu.Unlock()
	g.Stats.Bans.Add(1)
	return d, nil
}

func (g *Guard) overlapsNever(p netip.Prefix) bool {
	for _, n := range *g.never.Load() {
		if p.Overlaps(n) {
			return true
		}
	}
	return false
}

func prefixString(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// Unban removes a decision by id.
func (g *Guard) Unban(id int64) error {
	if g.Store != nil {
		if err := g.Store.RevokeDecision(id); err != nil {
			return err
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.decisions[:0:0]
	for _, d := range g.decisions {
		if d.ID != id {
			out = append(out, d)
		}
	}
	g.decisions = out
	g.rebuildBansLocked()
	return nil
}

// UnbanIP removes every decision for an address or CIDR and forgets its detector state.
func (g *Guard) UnbanIP(target string) error {
	p, ok := netinfo.ParsePrefix(target)
	if !ok {
		return errors.New("enter an IP address or CIDR")
	}
	key := prefixString(p)
	if g.Store != nil {
		if err := g.Store.RevokeIP(key); err != nil {
			return err
		}
	}
	g.states.Delete(key)
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.decisions[:0:0]
	for _, d := range g.decisions {
		if d.IP != key {
			out = append(out, d)
		}
	}
	g.decisions = out
	g.rebuildBansLocked()
	return nil
}

// ActiveBans returns unexpired decisions, newest first.
func (g *Guard) ActiveBans() []store.Decision {
	now := g.Now().Unix()
	g.mu.Lock()
	defer g.mu.Unlock()
	out := []store.Decision{}
	for _, d := range g.decisions {
		if d.ExpiresAt == 0 || d.ExpiresAt > now {
			out = append(out, d)
		}
	}
	return out
}

func (g *Guard) rebuildBansLocked() {
	now := g.Now().Unix()
	t := &banTable{exact: map[netip.Addr]store.Decision{}}
	live := g.decisions[:0:0]
	for _, d := range g.decisions {
		if d.ExpiresAt != 0 && d.ExpiresAt <= now {
			continue
		}
		live = append(live, d)
		p, ok := netinfo.ParsePrefix(d.IP)
		if !ok {
			continue
		}
		if p.IsSingleIP() {
			if _, dup := t.exact[p.Addr()]; !dup {
				t.exact[p.Addr()] = d
			}
		} else {
			t.prefixes = append(t.prefixes, prefixBan{p, d})
		}
	}
	g.decisions = live
	g.bans.Store(t)
}

// FeedStatus returns per-feed state.
func (g *Guard) FeedStatus() map[string]FeedStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]FeedStatus, len(g.feedStatus))
	for k, v := range g.feedStatus {
		out[k] = v
	}
	return out
}

// ThreatRanges is the size of the loaded threat set.
func (g *Guard) ThreatRanges() int { return g.set.Load().Len() }

// ExportOptions selects what the bouncer blocklist contains.
type ExportOptions struct {
	Feeds, Bans bool
	Family      int // 0 = both, 4 or 6
}

// WriteBlocklist writes a plain-text IP/CIDR list (one per line) for firewalls.
func (g *Guard) WriteBlocklist(w io.Writer, o ExportOptions) (int, error) {
	rc := g.cfg.Load()
	seen := map[string]bool{}
	var lines []string
	add := func(p netip.Prefix) {
		if (o.Family == 4 && !p.Addr().Is4()) || (o.Family == 6 && !p.Addr().Is6()) {
			return
		}
		if g.NeverBanned(p.Addr()) {
			return
		}
		s := prefixString(p)
		if !seen[s] {
			seen[s] = true
			lines = append(lines, s)
		}
	}
	if o.Bans {
		for _, d := range g.ActiveBans() {
			if p, ok := netinfo.ParsePrefix(d.IP); ok {
				add(p)
			}
		}
	}
	nBans := len(lines)
	if o.Feeds && rc.Enabled && rc.exportMask != 0 {
		for _, p := range g.set.Load().Prefixes(rc.exportMask) {
			add(p)
		}
	}
	sort.Strings(lines[nBans:])
	fmt.Fprintf(w, "# ZeroLeakage Guard blocklist, generated %s\n# %d active bans, %d entries in total\n",
		g.Now().UTC().Format(time.RFC3339), nBans, len(lines))
	for _, l := range lines {
		if _, err := io.WriteString(w, l+"\n"); err != nil {
			return 0, err
		}
	}
	return len(lines), nil
}

// RecordAlert queues an alert for the database (never blocks).
func (g *Guard) RecordAlert(a store.Alert) {
	if a.TS == 0 {
		a.TS = g.Now().UnixMilli()
	}
	g.Stats.Alerts.Add(1)
	select {
	case g.alertCh <- a:
	default:
	}
}

// Run writes alerts, expires bans, forgets idle detector state and refreshes feeds daily.
func (g *Guard) Run(ctx context.Context) {
	flush := time.NewTicker(2 * time.Second)
	sweep := time.NewTicker(time.Minute)
	daily := time.NewTicker(24 * time.Hour)
	defer flush.Stop()
	defer sweep.Stop()
	defer daily.Stop()
	var batch []store.Alert
	write := func() {
		if len(batch) > 0 && g.Store != nil {
			if err := g.Store.InsertAlerts(batch); err != nil {
				g.Log.Warn("guard alert write failed", "err", err)
			}
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			write()
			return
		case a := <-g.alertCh:
			batch = append(batch, a)
			if len(batch) >= 100 {
				write()
			}
		case <-flush.C:
			write()
		case <-sweep.C:
			g.mu.Lock()
			g.rebuildBansLocked()
			g.mu.Unlock()
			g.sweepStates()
		case <-daily.C:
			go g.RefreshFeeds(ctx, 23*time.Hour)
		}
	}
}
