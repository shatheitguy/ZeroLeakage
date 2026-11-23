package policy

import (
	"testing"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
)

func TestServices(t *testing.T) {
	m := LookupServices("r3---sn-abc.googlevideo.com")
	if s, ok := FirstService(m); !ok || s.ID != "youtube" {
		t.Fatalf("googlevideo should be YouTube: %v", s)
	}
	if LookupServices("example.com") != 0 {
		t.Fatal("example.com is no service")
	}
	if LookupServices("com") != 0 {
		t.Fatal("bare TLD matched")
	}
	tiktok := ServiceMask([]string{"tiktok", "nope"})
	if LookupServices("v16.tiktokcdn.com")&tiktok == 0 {
		t.Fatal("tiktok CDN not matched")
	}
	if ids := ServiceIDs(ServiceMask([]string{"netflix", "youtube"})); len(ids) != 2 || ids[0] != "youtube" {
		t.Fatalf("ServiceIDs order: %v", ids)
	}
	seen := map[string]bool{}
	for _, s := range Services {
		if seen[s.ID] || len(s.Domains) == 0 {
			t.Fatalf("bad catalog entry %q", s.ID)
		}
		seen[s.ID] = true
	}
}

func TestSafeSearch(t *testing.T) {
	ss := SafeSearch{Google: true, Bing: true, DuckDuckGo: true, YouTube: YouTubeMod}
	cases := map[string]string{
		"www.google.com":   googleSafe,
		"google.co.uk":     googleSafe,
		"www.google.de":    googleSafe,
		"mail.google.com":  "",
		"www.bing.com":     bingSafe,
		"duckduckgo.com":   ddgSafe,
		"www.youtube.com":  ytModerate,
		"m.youtube.com":    ytModerate,
		"i.ytimg.com":      "",
		"www.example.com":  "",
		"maps.google.com":  "",
		"youtube.com.evil": "",
	}
	for host, want := range cases {
		if got, _ := SafeTarget(host, ss); got != want {
			t.Errorf("SafeTarget(%s) = %q want %q", host, got, want)
		}
	}
	if got, _ := SafeTarget("www.google.com", SafeSearch{}); got != "" {
		t.Fatal("off must not rewrite")
	}
	strict := SafeSearch{YouTube: YouTubeStrct}.Stricter(SafeSearch{Google: true, YouTube: YouTubeMod})
	if !strict.Google || strict.YouTube != YouTubeStrct {
		t.Fatalf("Stricter: %+v", strict)
	}
	if got, _ := SafeTarget("www.youtube.com", strict); got != ytStrict {
		t.Fatalf("strict YouTube: %s", got)
	}
}

func TestScheduleWindows(t *testing.T) {
	loc := time.UTC
	at := func(day time.Weekday, h, m int) time.Time {
		// 2026-11-22 is a Sunday
		return time.Date(2026, 11, 22+int(day), h, m, 0, 0, loc)
	}
	bed := Schedule{Name: "Bedtime", Enabled: true, Days: []int{0, 1, 2, 3, 4}, Start: "21:00", End: "07:00", Action: ActionBlockAll}
	if err := bed.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		t    time.Time
		want bool
	}{
		{at(time.Sunday, 20, 59), false},
		{at(time.Sunday, 21, 0), true},
		{at(time.Monday, 6, 59), true}, // Sunday's window runs past midnight
		{at(time.Monday, 7, 0), false},
		{at(time.Thursday, 23, 0), true},
		{at(time.Friday, 3, 0), true},   // started Thursday
		{at(time.Friday, 22, 0), false}, // Friday is not a school night
		{at(time.Saturday, 2, 0), false},
	}
	for _, c := range cases {
		if got := bed.ActiveAt(c.t); got != c.want {
			t.Errorf("%s: active=%v want %v", c.t.Format("Mon 15:04"), got, c.want)
		}
	}
	homework := Schedule{Name: "Homework", Enabled: true, Days: []int{1}, Start: "16:00", End: "18:00", Action: ActionBlockSelected, Services: []string{"tiktok"}}
	if !homework.ActiveAt(at(time.Monday, 17, 0)) || homework.ActiveAt(at(time.Monday, 18, 0)) || homework.ActiveAt(at(time.Tuesday, 17, 0)) {
		t.Fatal("daytime window wrong")
	}
	allDay := Schedule{Name: "x", Enabled: true, Days: []int{6}, Start: "00:00", End: "00:00", Action: ActionBlockAll}
	if !allDay.ActiveAt(at(time.Saturday, 13, 0)) || allDay.ActiveAt(at(time.Sunday, 13, 0)) {
		t.Fatal("all-day window wrong")
	}
	bad := []Schedule{
		{Days: []int{1}, Start: "25:00", End: "07:00", Action: ActionBlockAll},
		{Days: []int{}, Start: "21:00", End: "07:00", Action: ActionBlockAll},
		{Days: []int{9}, Start: "21:00", End: "07:00", Action: ActionBlockAll},
		{Days: []int{1}, Start: "21:00", End: "07:00", Action: "explode"},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("bad schedule %d accepted", i)
		}
	}
}

func TestRewrites(t *testing.T) {
	tbl := NewRewrites([]Rewrite{
		{ID: "1", Domain: "nas.lan", Type: "A", Value: "192.168.1.10"},
		{ID: "2", Domain: "*.home.lan", Type: "A", Value: "192.168.1.20"},
		{ID: "3", Domain: "*.tv.home.lan", Type: "CNAME", Value: "nas.lan"},
		{ID: "4", Domain: "bad", Type: "A", Value: "not-an-ip"},
	})
	if rs := tbl.Lookup("nas.lan"); len(rs) != 1 || rs[0].Value != "192.168.1.10" {
		t.Fatalf("exact: %+v", rs)
	}
	if rs := tbl.Lookup("printer.home.lan"); len(rs) != 1 || rs[0].ID != "2" {
		t.Fatalf("wildcard: %+v", rs)
	}
	if rs := tbl.Lookup("a.b.home.lan"); len(rs) != 1 || rs[0].ID != "2" {
		t.Fatalf("deep wildcard: %+v", rs)
	}
	if rs := tbl.Lookup("living.tv.home.lan"); len(rs) != 1 || rs[0].ID != "3" {
		t.Fatalf("most specific wildcard: %+v", rs)
	}
	if tbl.Lookup("home.lan") != nil {
		t.Fatal("a wildcard must not match its bare parent")
	}
	if tbl.Lookup("bad") != nil {
		t.Fatal("invalid record compiled")
	}
	if h, ok := tbl.PTR("10.1.168.192.in-addr.arpa"); !ok || h != "nas.lan" {
		t.Fatalf("PTR: %q %v", h, ok)
	}
	for _, r := range []Rewrite{{Domain: "x.lan", Type: "AAAA", Value: "1.2.3.4"}, {Domain: "x.lan", Type: "MX", Value: "y"}, {Domain: "", Type: "A", Value: "1.2.3.4"}, {Domain: "x.lan", Type: "CNAME", Value: "x.lan"}} {
		if r.Validate() == nil {
			t.Errorf("invalid rewrite accepted: %+v", r)
		}
	}
}

func TestBypass(t *testing.T) {
	for _, d := range []string{"dns.google", "mozilla.cloudflare-dns.com", "dns.quad9.net", "abc123.dns.nextdns.io", "mask.icloud.com", "mask-h2.icloud.com", "doh.opendns.com", "dns.adguard-dns.com"} {
		if _, ok := BypassProvider(d); !ok {
			t.Errorf("%s should be a bypass host", d)
		}
	}
	for _, d := range []string{"google.com", "www.icloud.com", "cloudflare.com", "quad9.net", "example.com"} {
		if p, ok := BypassProvider(d); ok {
			t.Errorf("%s wrongly flagged as %s", d, p)
		}
	}
}

func TestCompilePrecedence(t *testing.T) {
	all := lists.Catalog
	net := Policy{Services: []string{"tiktok"}, Categories: []string{"ads", "cryptomining"}, SafeSearch: SafeSearch{Google: true}}
	user := Policy{Services: []string{"tiktok", "youtube"}, Categories: []string{"adult"}, SafeSearch: SafeSearch{YouTube: YouTubeStrct},
		CustomLists: []CustomList{{ID: "u1_x", Name: "Mine", URL: "https://example.com/l.txt", Category: "custom"}}}
	dev := Policy{Categories: []string{"gambling"}, Schedules: []Schedule{{Name: "Bed", Enabled: true, Days: []int{0}, Start: "21:00", End: "07:00", Action: ActionBlockAll}}}
	c := Compile(Input{
		Network: net, NetworkLists: []string{"trackers", "telemetry"}, User: &user, Device: &dev, AllLists: all,
		NetAllow: map[string]bool{"ok.example": true}, NetBlock: map[string]bool{"bad.example": true},
		UserAllow: map[string]bool{"bad.example": true, "mine.example": true}, DeviceBlock: map[string]bool{"dev.example": true},
	})
	if c.BaseServices != ServiceMask([]string{"tiktok"}) || c.ExtraServices != ServiceMask([]string{"youtube"}) {
		t.Fatalf("services: base %b extra %b", c.BaseServices, c.ExtraServices)
	}
	// nocoin comes in for crypto-mining (no enabled list of that category), ads is covered by trackers
	if !contains(c.BaseLists, "nocoin") || contains(c.BaseLists, "analytics") {
		t.Fatalf("base lists: %v", c.BaseLists)
	}
	if !contains(c.ExtraLists, "hagezi_nsfw") || !contains(c.ExtraLists, "hagezi_gambling") || !contains(c.ExtraLists, "u1_x") {
		t.Fatalf("extra lists: %v", c.ExtraLists)
	}
	if !c.SafeSearch.Google || c.SafeSearch.YouTube != YouTubeStrct {
		t.Fatalf("safe search: %+v", c.SafeSearch)
	}
	if c.Allow["bad.example"] || !c.Allow["mine.example"] {
		t.Fatalf("a network block must remove the user's allow: %v", c.Allow)
	}
	allow, block := c.EffectiveRules()
	if contains(allow, "bad.example") || !contains(allow, "ok.example") || !contains(block, "bad.example") || !contains(block, "dev.example") {
		t.Fatalf("effective rules: allow %v block %v", allow, block)
	}
	eff := c.Effective()
	if len(eff.Schedules) != 1 || !contains(eff.Categories, "adult") || !contains(eff.Categories, "ads") || len(eff.CustomLists) != 1 {
		t.Fatalf("effective: %+v", eff)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestNormalize(t *testing.T) {
	p := Policy{Services: []string{"youtube", "youtube", "nope"}, Categories: []string{"adult", "zzz"}, Lists: []string{"trackers", "x"},
		Schedules: []Schedule{{Name: "a", Enabled: true, Days: []int{1}, Start: "10:00", End: "11:00", Action: ActionBlockAll, Allow: []string{"*.school.example", "bad domain"}}}}
	if err := p.Normalize(func(id string) bool { return id == "trackers" }, true); err != nil {
		t.Fatal(err)
	}
	if len(p.Services) != 1 || len(p.Categories) != 1 || len(p.Lists) != 1 || len(p.Schedules[0].Allow) != 1 || p.SafeSearch.YouTube != YouTubeOff {
		t.Fatalf("normalize: %+v", p)
	}
	u := Policy{Schedules: p.Schedules, CustomLists: []CustomList{{ID: "u1_a", URL: "http://insecure.example/x"}}}
	if err := u.Normalize(func(string) bool { return true }, false); err == nil {
		t.Fatal("http custom list accepted")
	}
}
