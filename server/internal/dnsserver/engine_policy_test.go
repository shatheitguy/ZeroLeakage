package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/shatheitguy/ZeroLeakage/server/internal/guard"
	"github.com/shatheitguy/ZeroLeakage/server/internal/policy"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
)

func setNetwork(t *testing.T, e *Engine, st *store.Store, p policy.Policy) {
	t.Helper()
	if err := st.PutJSON(NetworkPolicyKey, p); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(e.Settings()); err != nil {
		t.Fatal(err)
	}
}

func askType(e *Engine, name string, qt uint16, c Client) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qt)
	return e.Handle(context.Background(), q, c)
}

var lan = Client{IP: "192.168.1.50", Proto: "udp"}

func TestBlockedServicesPerPolicy(t *testing.T) {
	e, st := newTestEngine(t)
	net := policy.DefaultNetwork()
	net.Services = []string{"tiktok"}
	setNetwork(t, e, st, net)

	if r := ask(e, "www.tiktok.com", lan); r.Rcode != dns.RcodeNameError {
		t.Fatalf("TikTok should be blocked network-wide")
	}
	if d := e.Decide("", "v16m.tiktokcdn.com"); !d.Blocked || d.Reason != "Blocked service: TikTok" || d.Service != "tiktok" {
		t.Fatalf("decision: %+v", d)
	}
	// a device adds YouTube on top of the baseline; others are unaffected
	kid, _ := st.CreateDevice(nil, "Kid", "lan", []string{"192.168.1.60"})
	_ = st.PutJSON("policy:device:"+kid.ID, policy.Policy{Services: []string{"youtube"}})
	_ = e.Reload(e.Settings())
	if r := ask(e, "www.youtube.com", Client{IP: "192.168.1.60"}); r.Rcode != dns.RcodeNameError {
		t.Fatal("kid device should have YouTube blocked")
	}
	if r := ask(e, "www.youtube.com", lan); r.Rcode != dns.RcodeSuccess {
		t.Fatal("other devices should reach YouTube")
	}
	// the device's allowlist cannot switch off a network-blocked service; the network allowlist can
	_ = st.SetRule("device:"+kid.ID, "allow", "tiktok.com", false)
	_ = e.Reload(e.Settings())
	if d := e.Decide(kid.ID, "www.tiktok.com"); !d.Blocked {
		t.Fatal("device allow must not beat the network baseline")
	}
	_ = st.SetRule("default", "allow", "tiktok.com", false)
	_ = e.Reload(e.Settings())
	if d := e.Decide(kid.ID, "www.tiktok.com"); d.Blocked {
		t.Fatal("network allow should unblock")
	}
	// a device allow can lift the device's own additions
	_ = st.SetRule("device:"+kid.ID, "allow", "youtube.com", false)
	_ = e.Reload(e.Settings())
	if d := e.Decide(kid.ID, "www.youtube.com"); d.Blocked {
		t.Fatal("device allow should lift a device-level service block")
	}
}

func TestNetworkBlockBeatsUserAllow(t *testing.T) {
	e, st := newTestEngine(t)
	uid := int64(1)
	if _, err := st.CreateUser("sam", "x", false); err != nil {
		t.Fatal(err)
	}
	phone, _ := st.CreateDevice(&uid, "Phone", "app", nil)
	_ = st.SetRule("default", "block", "bad.example", false)
	_ = st.SetRule(UserScope(uid), "allow", "bad.example", false)
	_ = st.SetRule(UserScope(uid), "allow", "doubleclick.net", false)
	_ = e.Reload(e.Settings())
	if d := e.Decide(phone.ID, "www.bad.example"); !d.Blocked || d.Reason != "Network blocklist" {
		t.Fatalf("network block must win over user allow: %+v", d)
	}
	// lists enabled by the admin cannot be switched off by a user allow either
	if d := e.Decide(phone.ID, "doubleclick.net"); !d.Blocked {
		t.Fatalf("network list must win over user allow: %+v", d)
	}
}

func TestCategoriesToggle(t *testing.T) {
	e, st := newTestEngine(t)
	if d := e.Decide("", "coinhive.com"); !d.Blocked || d.Category != "malware" {
		t.Fatalf("malware category on by default: %+v", d)
	}
	net := policy.DefaultNetwork()
	net.Categories = []string{"ads"}
	setNetwork(t, e, st, net)
	if d := e.Decide("", "coinhive.com"); d.Blocked || d.Category != "malware" {
		t.Fatalf("malware off: should resolve but stay tagged: %+v", d)
	}
	if d := e.Decide("", "doubleclick.net"); !d.Blocked {
		t.Fatal("ads still on")
	}
	ids := strings.Join(e.ListIDs(), ",")
	if strings.Contains(ids, "malware") || !strings.Contains(ids, "trackers") {
		t.Fatalf("lists in use: %s", ids)
	}
}

func TestSafeSearchCNAME(t *testing.T) {
	e, st := newTestEngine(t)
	net := policy.DefaultNetwork()
	net.SafeSearch = policy.SafeSearch{Google: true, YouTube: policy.YouTubeMod}
	setNetwork(t, e, st, net)
	r := ask(e, "www.google.com", lan)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 2 {
		t.Fatalf("want CNAME + A, got %v", r)
	}
	if c, ok := r.Answer[0].(*dns.CNAME); !ok || c.Target != "forcesafesearch.google.com." {
		t.Fatalf("CNAME: %v", r.Answer[0])
	}
	if a, ok := r.Answer[1].(*dns.A); !ok || a.Hdr.Name != "forcesafesearch.google.com." {
		t.Fatalf("A: %v", r.Answer[1])
	}
	if c := ask(e, "www.youtube.com", lan).Answer[0].(*dns.CNAME); c.Target != "restrictmoderate.youtube.com." {
		t.Fatalf("YouTube: %v", c)
	}
	if r := ask(e, "mail.google.com", lan); len(r.Answer) != 1 {
		t.Fatal("mail.google.com must not be rewritten")
	}
	// SafeSearch is per policy: the shared cache must not leak it
	net.SafeSearch = policy.SafeSearch{}
	setNetwork(t, e, st, net)
	if r := ask(e, "www.google.com", lan); len(r.Answer) != 1 {
		t.Fatalf("SafeSearch off: plain answer expected, got %v", r.Answer)
	}
}

func TestLocalRecords(t *testing.T) {
	e, st := newTestEngine(t)
	_ = st.PutJSON(RewritesKey, []policy.Rewrite{
		{ID: "1", Domain: "nas.lan", Type: "A", Value: "192.168.1.10"},
		{ID: "2", Domain: "*.home.lan", Type: "A", Value: "192.168.1.20"},
		{ID: "3", Domain: "alias.lan", Type: "CNAME", Value: "example.org"},
		{ID: "4", Domain: "files.lan", Type: "CNAME", Value: "nas.lan"},
	})
	_ = e.Reload(e.Settings())
	before := calls.Load()
	r := ask(e, "nas.lan", lan)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.10" || !r.Authoritative {
		t.Fatalf("A record: %v", r)
	}
	if r := askType(e, "nas.lan", dns.TypeAAAA, lan); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("AAAA should be NODATA: %v", r)
	}
	if r := ask(e, "printer.home.lan", lan); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.20" {
		t.Fatalf("wildcard: %v", r)
	}
	if r := ask(e, "files.lan", lan); len(r.Answer) != 2 || r.Answer[1].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatalf("local CNAME chain: %v", r)
	}
	if calls.Load() != before {
		t.Fatal("local records must not reach the upstream")
	}
	if r := ask(e, "alias.lan", lan); len(r.Answer) != 2 || r.Answer[1].(*dns.A).A.String() != "203.0.113.7" {
		t.Fatalf("CNAME to upstream: %v", r)
	}
	if r := askType(e, "10.1.168.192.in-addr.arpa", dns.TypePTR, lan); len(r.Answer) != 1 || r.Answer[0].(*dns.PTR).Ptr != "nas.lan." {
		t.Fatalf("PTR: %v", r)
	}
}

func TestBypassBlocking(t *testing.T) {
	e, _ := newTestEngine(t)
	e.SetSelf("192.168.1.2")
	if r := ask(e, "dns.google", lan); r.Rcode != dns.RcodeNameError {
		t.Fatal("LAN clients must not reach public DoH")
	}
	if d := e.DecideFor("", "192.168.1.50", "mask.icloud.com", dns.TypeA); !d.Blocked || !strings.HasPrefix(d.Reason, "Filtering bypass") {
		t.Fatalf("iCloud Private Relay: %+v", d)
	}
	if r := ask(e, "dns.google", Client{IP: "192.168.1.2"}); r.Rcode != dns.RcodeSuccess {
		t.Fatal("the server itself must never be affected")
	}
	if r := ask(e, "dns.google", Client{IP: "127.0.0.1"}); r.Rcode != dns.RcodeSuccess {
		t.Fatal("loopback is the server itself")
	}
	if r := ask(e, "dns.google", Client{IP: "203.0.113.9", Proto: "doh"}); r.Rcode != dns.RcodeSuccess {
		t.Fatal("mode lan: internet DoH clients are not affected")
	}
	st := e.Settings()
	st.BlockBypass = policy.BypassAll
	_ = e.Reload(st)
	if r := ask(e, "dns.google", Client{IP: "203.0.113.9", Proto: "doh"}); r.Rcode != dns.RcodeNameError {
		t.Fatal("mode all blocks everyone")
	}
	st.BlockBypass = policy.BypassOff
	_ = e.Reload(st)
	if r := ask(e, "dns.google", lan); r.Rcode != dns.RcodeSuccess {
		t.Fatal("mode off")
	}
	if r := ask(e, "use-application-dns.net", lan); r.Rcode != dns.RcodeNameError {
		t.Fatal("the Firefox canary is always NXDOMAIN")
	}
}

func TestSchedules(t *testing.T) {
	e, st := newTestEngine(t)
	now := time.Date(2026, 11, 23, 22, 0, 0, 0, time.Local) // Monday 22:00
	e.Now = func() time.Time { return now }
	kid, _ := st.CreateDevice(nil, "Kid", "lan", []string{"192.168.1.60"})
	_ = st.PutJSON("policy:device:"+kid.ID, policy.Policy{Schedules: []policy.Schedule{
		{Name: "Bedtime", Enabled: true, Days: []int{0, 1, 2, 3, 4}, Start: "21:00", End: "07:00", Action: policy.ActionBlockAll, Allow: []string{"school.example"}},
		{Name: "Homework", Enabled: true, Days: []int{1}, Start: "16:00", End: "18:00", Action: policy.ActionBlockSelected, Services: []string{"youtube"}},
	}})
	_ = e.Reload(e.Settings())
	kidC := Client{IP: "192.168.1.60"}
	if r := ask(e, "example.org", kidC); r.Rcode != dns.RcodeNameError {
		t.Fatal("bedtime should block everything")
	}
	if d := e.Decide(kid.ID, "example.org"); d.Reason != "Schedule: Bedtime" {
		t.Fatalf("reason: %q", d.Reason)
	}
	if r := ask(e, "www.school.example", kidC); r.Rcode != dns.RcodeSuccess {
		t.Fatal("schedule allowlist")
	}
	if r := ask(e, "example.org", lan); r.Rcode != dns.RcodeSuccess {
		t.Fatal("other devices unaffected")
	}
	now = time.Date(2026, 11, 23, 17, 0, 0, 0, time.Local)
	if d := e.Decide(kid.ID, "www.youtube.com"); !d.Blocked || d.Reason != "Schedule Homework: YouTube" {
		t.Fatalf("homework: %+v", d)
	}
	if d := e.Decide(kid.ID, "example.org"); d.Blocked {
		t.Fatal("homework blocks only YouTube")
	}
	now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.Local)
	if d := e.Decide(kid.ID, "www.youtube.com"); d.Blocked {
		t.Fatal("no schedule at noon")
	}
}

func TestGuardInDNS(t *testing.T) {
	e, st := newTestEngine(t)
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "guard"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "guard", "spamhaus_drop.txt"), []byte("198.51.100.0/24 ; SBL1\n"), 0o644)
	g := guard.New(st, dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.SelfAddrs = func() []netip.Addr { return nil }
	g.Gateways = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.1")} }
	cfg := guard.DefaultConfig()
	cfg.DNSFeeds, cfg.ExportFeeds = []string{"spamhaus_drop"}, []string{"spamhaus_drop"}
	cfg.QuarantineAllow = []string{"school.example"}
	if _, err := g.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	g.RefreshFeeds(context.Background(), 0)
	e.Guard = g

	if r := ask(e, "c2host.example", lan); r.Rcode != dns.RcodeNameError {
		t.Fatalf("answer pointing at a DROP netblock must be blocked: %v", r)
	}
	if r := ask(e, "example.org", lan); r.Rcode != dns.RcodeSuccess {
		t.Fatal("clean answer")
	}
	// LAN ban = quarantine
	if _, err := g.Ban("192.168.1.70", guard.ScenarioManual, "test", "manual", 30); err != nil {
		t.Fatal(err)
	}
	q := Client{IP: "192.168.1.70"}
	if r := ask(e, "example.org", q); r.Rcode != dns.RcodeNameError {
		t.Fatal("quarantined client should be blocked")
	}
	if r := ask(e, "www.school.example", q); r.Rcode != dns.RcodeSuccess {
		t.Fatal("quarantine allowlist should resolve")
	}
	// internet client ban = refuse
	if _, err := g.Ban("203.0.113.50", guard.ScenarioManual, "test", "manual", 30); err != nil {
		t.Fatal(err)
	}
	if r := ask(e, "example.org", Client{IP: "203.0.113.50", Proto: "doh"}); r.Rcode != dns.RcodeRefused {
		t.Fatalf("public ban should refuse, got %s", dns.RcodeToString[r.Rcode])
	}
	if _, err := g.Ban("192.168.1.1", guard.ScenarioManual, "x", "manual", 30); err != guard.ErrNeverBan {
		t.Fatal("gateway must be on the never-ban list")
	}
	e.FlushLog()
	rows, _ := st.Queries(store.QueryFilter{Client: "192.168.1.70"})
	if len(rows) == 0 || !strings.HasPrefix(rows[len(rows)-1].Reason, "Quarantined") {
		t.Fatalf("query log: %+v", rows)
	}
}

func TestQueryLogTags(t *testing.T) {
	e, st := newTestEngine(t)
	net := policy.DefaultNetwork()
	net.Services = []string{"tiktok"}
	setNetwork(t, e, st, net)
	ask(e, "www.tiktok.com", lan)
	ask(e, "www.youtube.com", lan)
	ask(e, "doubleclick.net", lan)
	e.FlushLog()
	rep, err := st.Report(store.ReportFilter{Since: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 3 || rep.Blocked != 2 || len(rep.TopServices) != 2 || len(rep.TopCategories) != 1 || rep.TopCategories[0].Name != "ads" {
		t.Fatalf("report: %+v", rep)
	}
}
