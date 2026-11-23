package guard

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseFeed(t *testing.T) {
	in := `; Spamhaus DROP List
1.10.16.0/20 ; SBL256894
# comment
0.0.0.0/8
10.0.0.0/8
224.0.0.0/3
192.168.1.1
2001:678:254::/48 ; SBL697648
162.243.103.246
garbage line
::ffff:5.6.7.8
fe80::1
`
	got := ParseFeed(strings.NewReader(in))
	want := []string{"1.10.16.0/20", "2001:678:254::/48", "162.243.103.246/32", "5.6.7.8/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, p := range got {
		if p.String() != want[i] {
			t.Fatalf("entry %d = %s want %s", i, p, want[i])
		}
	}
}

func TestSetLookupAndExport(t *testing.T) {
	b := &Builder{}
	b.Add(netip.MustParsePrefix("10.0.0.0/8"), 0)  // feed 0: wide
	b.Add(netip.MustParsePrefix("10.1.0.0/16"), 1) // feed 1 overlaps feed 0
	b.Add(netip.MustParsePrefix("10.1.0.0/24"), 0) // overlap inside the same feed
	b.Add(netip.MustParsePrefix("203.0.113.7/32"), 2)
	b.Add(netip.MustParsePrefix("2001:db8::/32"), 1)
	s := b.Build()
	cases := map[string]uint32{
		"10.0.0.1":      1,
		"10.1.0.5":      3,
		"10.1.200.1":    3,
		"10.2.0.1":      1,
		"11.0.0.0":      0,
		"203.0.113.7":   4,
		"203.0.113.8":   0,
		"2001:db8::1":   2,
		"2001:db9::1":   0,
		"9.255.255.255": 0,
	}
	for ip, want := range cases {
		if got := s.Lookup(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Lookup(%s) = %b want %b", ip, got, want)
		}
	}
	ps := s.Prefixes(1 << 1)
	if fmt.Sprint(ps) != "[10.1.0.0/16 2001:db8::/32]" {
		t.Fatalf("feed-1 export = %v", ps)
	}
	all := s.Prefixes(^uint32(0))
	if fmt.Sprint(all) != "[10.0.0.0/8 203.0.113.7/32 2001:db8::/32]" {
		t.Fatalf("full export = %v", all)
	}
	// an unaligned range splits into aligned blocks
	b2 := &Builder{}
	b2.Add(netip.MustParsePrefix("1.0.0.1/32"), 0)
	b2.Add(netip.MustParsePrefix("1.0.0.2/31"), 0)
	b2.Add(netip.MustParsePrefix("1.0.0.4/32"), 0)
	if got := fmt.Sprint(b2.Build().Prefixes(1)); got != "[1.0.0.1/32 1.0.0.2/31 1.0.0.4/32]" {
		t.Fatalf("split = %s", got)
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func addrs(s ...string) func() []netip.Addr {
	return func() []netip.Addr {
		var out []netip.Addr
		for _, x := range s {
			out = append(out, netip.MustParseAddr(x))
		}
		return out
	}
}

func newGuard(t *testing.T) (*Guard, *clock) {
	t.Helper()
	g := New(nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	c := &clock{time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	g.Now = c.now
	g.SelfAddrs = addrs("192.168.1.2")
	g.Gateways = addrs("192.168.1.1")
	cfg := DefaultConfig()
	cfg.Flood.Threshold, cfg.Flood.WindowSec = 5, 10 // 50 queries in 10 s
	cfg.NXDomain.Threshold = 20
	cfg.Tunnel.Threshold = 20
	cfg.Malware.Threshold = 3
	cfg.BruteForce.Threshold = 4
	if _, err := g.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	return g, c
}

func alerts(g *Guard) []string {
	var out []string
	for {
		select {
		case a := <-g.alertCh:
			out = append(out, a.Scenario+":"+a.Action)
		default:
			return out
		}
	}
}

func TestFloodBanAndExpiry(t *testing.T) {
	g, c := newGuard(t)
	ip := netip.MustParseAddr("192.168.1.50")
	for i := 0; i < 49; i++ {
		g.ObserveQuery(ip, "", "example.com", dns.TypeA)
	}
	if g.Banned(ip) != nil {
		t.Fatal("banned below the threshold")
	}
	g.ObserveQuery(ip, "", "example.com", dns.TypeA)
	d := g.Banned(ip)
	if d == nil || d.Scenario != ScenarioFlood {
		t.Fatalf("flood should ban: %+v", d)
	}
	if got := alerts(g); len(got) != 1 || got[0] != "dns_flood:ban" {
		t.Fatalf("alerts: %v", got)
	}
	if g.Effect(ip) != EffectQuarantine || g.Effect(netip.MustParseAddr("8.8.8.8")) != EffectRefuse {
		t.Fatal("default ban effects")
	}
	c.add(9 * time.Minute)
	if g.Banned(ip) == nil {
		t.Fatal("ban expired early")
	}
	c.add(2 * time.Minute)
	if g.Banned(ip) != nil {
		t.Fatal("ban should expire after 10 minutes")
	}
	if len(g.ActiveBans()) != 0 {
		t.Fatal("expired ban still listed")
	}
}

func TestNeverBan(t *testing.T) {
	g, _ := newGuard(t)
	for _, ip := range []string{"192.168.1.1", "192.168.1.2", "127.0.0.1"} {
		if _, err := g.Ban(ip, ScenarioManual, "x", "manual", 10); err != ErrNeverBan {
			t.Errorf("%s: want ErrNeverBan, got %v", ip, err)
		}
	}
	if _, err := g.Ban("192.168.0.0/16", ScenarioManual, "x", "manual", 10); err != ErrNeverBan {
		t.Error("a CIDR covering the gateway must be refused")
	}
	// flood from the gateway (all LAN traffic behind a NAT'd router) only alerts
	gw := netip.MustParseAddr("192.168.1.1")
	for i := 0; i < 60; i++ {
		g.ObserveQuery(gw, "", "example.com", dns.TypeA)
	}
	if g.Banned(gw) != nil {
		t.Fatal("gateway banned")
	}
	if got := alerts(g); len(got) != 1 || got[0] != "dns_flood:alert" {
		t.Fatalf("alerts: %v", got)
	}
	// manual CIDR ban + unban
	d, err := g.Ban("203.0.113.0/24", ScenarioManual, "test", "manual", 0)
	if err != nil {
		t.Fatal(err)
	}
	if g.Banned(netip.MustParseAddr("203.0.113.9")) == nil {
		t.Fatal("CIDR ban not applied")
	}
	if err := g.Unban(d.ID); err != nil || g.Banned(netip.MustParseAddr("203.0.113.9")) != nil {
		t.Fatal("unban failed")
	}
}

func TestNXDomainStorm(t *testing.T) {
	g, _ := newGuard(t)
	ip := netip.MustParseAddr("192.168.1.60")
	for i := 0; i < 50; i++ { // the same name again and again is not a storm
		g.ObserveAnswer(ip, "", "typo.example", dns.RcodeNameError)
	}
	if len(alerts(g)) != 0 {
		t.Fatal("repeated name triggered")
	}
	for i := 0; i < 20; i++ {
		g.ObserveAnswer(ip, "dev1", fmt.Sprintf("x%dqzk.example", i), dns.RcodeNameError)
	}
	if got := alerts(g); len(got) != 1 || got[0] != "nxdomain_storm:alert" {
		t.Fatalf("alerts: %v", got)
	}
}

func TestTunnelHeuristic(t *testing.T) {
	g, _ := newGuard(t)
	cfg := g.Config()
	cfg.Flood.Enabled = false
	_, _ = g.SetConfig(cfg)
	ip := netip.MustParseAddr("192.168.1.61")
	for i := 0; i < 30; i++ { // normal: few distinct, readable names
		g.ObserveQuery(ip, "", fmt.Sprintf("www%d.example.com", i%3), dns.TypeA)
	}
	for i := 0; i < 25; i++ { // many distinct readable names on a CDN: not suspicious
		g.ObserveQuery(ip, "", fmt.Sprintf("img%d.cdn.example.net", i), dns.TypeA)
	}
	if len(alerts(g)) != 0 {
		t.Fatal("benign traffic flagged")
	}
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("%016x%016x.t.evil.example", uint64(i+1)*0x9e3779b97f4a7c15, uint64(i+7)*0x5851f42d4c957f2d)
		g.ObserveQuery(ip, "", name, dns.TypeTXT)
	}
	if got := alerts(g); len(got) != 1 || got[0] != "dns_tunnel:alert" {
		t.Fatalf("alerts: %v", got)
	}
	if sub, parent := splitParent("a.b.example.co.uk"); sub != "a.b" || parent != "example.co.uk" {
		t.Fatalf("splitParent: %q %q", sub, parent)
	}
	if !suspiciousLabel("aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbHRyYXRlZCBkYXRh", dns.TypeA) || suspiciousLabel("www", dns.TypeA) {
		t.Fatal("suspiciousLabel")
	}
}

func TestMalwareAndBruteForce(t *testing.T) {
	g, _ := newGuard(t)
	ip := netip.MustParseAddr("192.168.1.62")
	for i := 0; i < 3; i++ {
		g.ObserveMalware(ip, "kid", "c2.bad.example")
	}
	if got := alerts(g); len(got) != 1 || got[0] != "infected_device:alert" {
		t.Fatalf("malware alerts: %v", got)
	}
	attacker := netip.MustParseAddr("198.51.100.20")
	for i := 0; i < 4; i++ {
		g.LoginFailure(attacker)
	}
	if d := g.Banned(attacker); d == nil || d.Scenario != ScenarioBruteForce {
		t.Fatalf("brute force should ban: %+v", d)
	}
	var sb strings.Builder
	n, _ := g.WriteBlocklist(&sb, ExportOptions{Bans: true})
	if n != 1 || !strings.Contains(sb.String(), "198.51.100.20\n") {
		t.Fatalf("export: %q", sb.String())
	}
}

func TestQuarantineAllow(t *testing.T) {
	g, _ := newGuard(t)
	cfg := g.Config()
	cfg.QuarantineAllow = []string{"school.example"}
	if _, err := g.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if !g.QuarantineAllows("www.school.example") || g.QuarantineAllows("evil.example") || !g.QuarantineAllows("dns.home.example", "dns.home.example") {
		t.Fatal("quarantine allowlist")
	}
}
