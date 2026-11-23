package filter

import (
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		in     string
		suffix bool
		want   Rule
		ok     bool
	}{
		{"||doubleclick.net^", false, Rule{BlockSuffix, "doubleclick.net"}, true},
		{"||ads.example.com^$important", false, Rule{BlockSuffix, "ads.example.com"}, true},
		{"@@||good.example.com^", false, Rule{AllowSuffix, "good.example.com"}, true},
		{"0.0.0.0 tracker.example.org", false, Rule{BlockExact, "tracker.example.org"}, true},
		{"127.0.0.1 localhost", false, Rule{}, false},
		{"telemetry.example.net", true, Rule{BlockSuffix, "telemetry.example.net"}, true},
		{"! comment", false, Rule{}, false},
		{"example.com##.banner", false, Rule{}, false},
		{"||example.com/path^", false, Rule{}, false},
		{"||example.com^$dnstype=AAAA", false, Rule{}, false},
		{"/regex.*/", false, Rule{}, false},
		{"1.2.3.4", false, Rule{}, false},
		{"com", false, Rule{}, false},
	}
	for _, c := range cases {
		got, ok := ParseLine(c.in, c.suffix)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseLine(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestMatchPrecedence(t *testing.T) {
	b := NewBuilder()
	b.AddList(Source{ID: "a", Name: "List A", Category: "Ads", CategoryID: "ads"}, strings.NewReader("||ads.com^\n0.0.0.0 exact.org\n@@||ok.ads.com^\n"), false)
	idx := b.Build()

	if m := idx.Match("x.ads.com", nil, nil, AllLists); m == nil || !m.Blocked || m.Matched != "ads.com" {
		t.Fatalf("suffix block failed: %+v", m)
	}
	if m := idx.Match("ok.ads.com", nil, nil, AllLists); m == nil || m.Blocked {
		t.Fatalf("list exception failed: %+v", m)
	}
	if m := idx.Match("exact.org", nil, nil, AllLists); m == nil || !m.Blocked {
		t.Fatalf("exact block failed: %+v", m)
	}
	if m := idx.Match("sub.exact.org", nil, nil, AllLists); m != nil {
		t.Fatalf("exact rule must not match subdomain: %+v", m)
	}
	if m := idx.Match("x.ads.com", map[string]bool{"ads.com": true}, nil, AllLists); m == nil || m.Blocked || m.ListID != UserAllowID {
		t.Fatalf("user allow must win: %+v", m)
	}
	if m := idx.Match("google.com", nil, map[string]bool{"google.com": true}, AllLists); m == nil || !m.Blocked || m.ListID != UserBlockID {
		t.Fatalf("user block failed: %+v", m)
	}
	if m := idx.Match("google.com", nil, nil, AllLists); m != nil {
		t.Fatalf("unlisted domain matched: %+v", m)
	}
	if idx.TotalRules() != 3 {
		t.Fatalf("TotalRules = %d", idx.TotalRules())
	}
}

func TestListMasks(t *testing.T) {
	b := NewBuilder()
	b.AddList(Source{ID: "ads", Name: "Ads", Category: "Ads & trackers", CategoryID: "ads"}, strings.NewReader("||tracker.com^\n||shared.com^\n"), false)
	b.AddList(Source{ID: "adult", Name: "Adult", Category: "Adult", CategoryID: "adult"}, strings.NewReader("||porn.example^\n||shared.com^\n@@||ok.porn.example^\n"), false)
	idx := b.Build()
	ads, adult := idx.Mask([]string{"ads"}), idx.Mask([]string{"adult", "unknown"})
	if ads != 1 || adult != 2 {
		t.Fatalf("masks: %b %b", ads, adult)
	}
	// adult list not selected: not blocked, but the query is still tagged with its category
	m, seen := idx.MatchLists("www.porn.example", ads)
	if m != nil || seen != adult {
		t.Fatalf("unselected list must not block: %+v seen=%b", m, seen)
	}
	if id, _ := idx.CategoryOf(seen); id != "adult" {
		t.Fatalf("category tag = %q", id)
	}
	if m, _ := idx.MatchLists("www.porn.example", ads|adult); m == nil || !m.Blocked || m.CategoryID != "adult" {
		t.Fatalf("selected list must block: %+v", m)
	}
	// the exception only applies when its list is selected
	if m, _ := idx.MatchLists("ok.porn.example", adult); m == nil || m.Blocked {
		t.Fatalf("list exception: %+v", m)
	}
	// a domain in two lists reports the first selected one
	if m, _ := idx.MatchLists("shared.com", adult); m == nil || m.ListID != "adult" {
		t.Fatalf("shared domain: %+v", m)
	}
	if idx.Gen == Empty.Gen || idx.Gen == 0 {
		t.Fatal("index generation must be unique")
	}
}

func TestIndexFull(t *testing.T) {
	b := NewBuilder()
	for i := 0; i < MaxSources; i++ {
		id := string(rune('a'+i%26)) + string(rune('a'+i/26))
		if n := b.AddList(Source{ID: id}, strings.NewReader("x.com\n"), false); n != 1 {
			t.Fatalf("list %d: %d", i, n)
		}
	}
	if n := b.AddList(Source{ID: "overflow"}, strings.NewReader("y.com\n"), false); n != -1 {
		t.Fatalf("65th list must be refused, got %d", n)
	}
}
