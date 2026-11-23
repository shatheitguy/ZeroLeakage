package dnsserver

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
	"github.com/shatheitguy/ZeroLeakage/server/internal/upstream"
)

var calls atomic.Int64

// fakeDoH answers every A query with 203.0.113.7, except cloaked.example.com which is a CNAME to doubleclick.net.
func fakeDoH(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			t.Errorf("bad upstream query: %v", err)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		name := q.Question[0].Name
		calls.Add(1)
		switch name {
		case "nx.example.com.":
			m.Rcode = dns.RcodeNameError
			out, _ := m.Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(out)
			return
		case "c2host.example.":
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.66")})
			out, _ := m.Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(out)
			return
		}
		if q.Question[0].Qtype == dns.TypeAAAA {
			out, _ := m.Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(out)
			return
		}
		if name == "cloaked.example.com." {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "stats.doubleclick.net."})
		}
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.7")})
		out, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
}

func newTestEngine(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	lm := lists.NewManager(dir, log)
	lm.Rebuild(context.Background(), []string{"telemetry", "trackers", "analytics", "malware"}, 0) // built-in only, no network
	srv := fakeDoH(t)
	t.Cleanup(srv.Close)
	up := upstream.New(upstream.Resolver{ID: "fake", Name: "Fake", URL: srv.URL}, nil, nil)
	e := NewEngine(lm, up, st, log)
	settings := store.DefaultSettings(nil)
	if err := e.Reload(settings); err != nil {
		t.Fatal(err)
	}
	return e, st
}

func ask(e *Engine, name string, c Client) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return e.Handle(context.Background(), q, c)
}

func TestBlockAndAllow(t *testing.T) {
	e, st := newTestEngine(t)
	lan := Client{IP: "192.168.1.50", Proto: "udp"}

	if r := ask(e, "doubleclick.net", lan); r.Rcode != dns.RcodeNameError {
		t.Fatalf("tracker should be NXDOMAIN, got %s", dns.RcodeToString[r.Rcode])
	}
	if r := ask(e, "ad.doubleclick.net", lan); r.Rcode != dns.RcodeNameError {
		t.Fatalf("tracker subdomain should be blocked")
	}
	r := ask(e, "example.org", lan)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("clean domain should resolve, got %v", r)
	}
	// second lookup is served from cache
	ask(e, "example.org", lan)
	if e.Counters.Cached.Load() != 1 {
		t.Fatalf("expected one cache hit, got %d", e.Counters.Cached.Load())
	}
	// user allow beats the list
	if err := st.SetRule("default", "allow", "doubleclick.net", false); err != nil {
		t.Fatal(err)
	}
	_ = e.Reload(e.Settings())
	if r := ask(e, "doubleclick.net", lan); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("allowlisted tracker should resolve")
	}
	// user block
	_ = st.SetRule("default", "block", "example.org", false)
	_ = e.Reload(e.Settings())
	if r := ask(e, "www.example.org", lan); r.Rcode != dns.RcodeNameError {
		t.Fatalf("user-blocked domain should be NXDOMAIN")
	}
}

func TestCNAMECloakingAndNullIP(t *testing.T) {
	e, _ := newTestEngine(t)
	if r := ask(e, "cloaked.example.com", Client{IP: "10.0.0.2"}); r.Rcode != dns.RcodeNameError {
		t.Fatalf("CNAME to a tracker should be blocked, got %s", dns.RcodeToString[r.Rcode])
	}
	st := e.Settings()
	st.BlockMode = "null_ip"
	_ = e.Reload(st)
	r := ask(e, "doubleclick.net", Client{IP: "10.0.0.2"})
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
		t.Fatalf("null_ip mode should answer 0.0.0.0, got %v", r)
	}
}

func TestDevicePolicyByIPAndDoHPath(t *testing.T) {
	e, st := newTestEngine(t)
	kid, _ := st.CreateDevice(nil, "Kid tablet", "lan", []string{"192.168.1.60"})
	phone, _ := st.CreateDevice(nil, "Phone", "app", nil)
	_ = st.SetRule("device:"+kid.ID, "block", "youtube.com", false)
	_ = st.SetRule("device:"+phone.ID, "block", "reddit.com", false)
	_ = e.Reload(e.Settings())

	if r := ask(e, "www.youtube.com", Client{IP: "192.168.1.60"}); r.Rcode != dns.RcodeNameError {
		t.Fatal("kid tablet (by IP) should have youtube blocked")
	}
	if r := ask(e, "www.youtube.com", Client{IP: "192.168.1.61"}); r.Rcode != dns.RcodeSuccess {
		t.Fatal("other LAN devices should resolve youtube")
	}

	h := DoHHandler(e, false)
	q := new(dns.Msg)
	q.SetQuestion("reddit.com.", dns.TypeA)
	wire, _ := q.Pack()
	for path, want := range map[string]int{"/dns-query/" + phone.ID: dns.RcodeNameError, "/dns-query": dns.RcodeSuccess} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/dns-message")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		m := new(dns.Msg)
		if err := m.Unpack(rec.Body.Bytes()); err != nil {
			t.Fatalf("%s: bad DoH response: %v (%d)", path, err, rec.Code)
		}
		if m.Rcode != want {
			t.Fatalf("%s: rcode %s, want %s", path, dns.RcodeToString[m.Rcode], dns.RcodeToString[want])
		}
	}

	// paused device: no filtering at all
	kid.Paused = true
	_ = st.UpdateDevice(kid)
	_ = e.Reload(e.Settings())
	if r := ask(e, "doubleclick.net", Client{IP: "192.168.1.60"}); r.Rcode != dns.RcodeSuccess {
		t.Fatal("paused device should not be filtered")
	}
}

func TestDeviceFromSNI(t *testing.T) {
	cases := map[[2]string]string{
		{"abc123xyz0.dns.example.com", "dns.example.com"}: "abc123xyz0",
		{"dns.example.com", "dns.example.com"}:            "",
		{"a.b.dns.example.com", "dns.example.com"}:        "",
		{"abc.other.com", "dns.example.com"}:              "",
		{"abc.dns.example.com.", ""}:                      "",
	}
	for in, want := range cases {
		if got := DeviceFromSNI(in[0], in[1]); got != want {
			t.Errorf("DeviceFromSNI(%q,%q)=%q want %q", in[0], in[1], got, want)
		}
	}
}
