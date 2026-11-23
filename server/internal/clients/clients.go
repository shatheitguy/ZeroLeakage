// Package clients discovers the devices that use the server: source address, first/last seen and
// query counts from DNS traffic, host names from the LAN's own resolver (reverse DNS), and MAC address
// plus vendor from the kernel ARP table when running with host networking. Nothing leaves the LAN:
// reverse lookups go only to the configured local resolver and only for private addresses.
package clients

import (
	"bufio"
	"context"
	_ "embed"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/shatheitguy/ZeroLeakage/server/internal/netinfo"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
)

//go:embed oui.txt
var ouiData string

var (
	ouiOnce sync.Once
	ouiMap  map[uint32]string
)

func loadOUI() {
	ouiMap = make(map[uint32]string, 16384)
	for _, line := range strings.Split(ouiData, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		vendor, prefixes, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		for _, p := range strings.Split(prefixes, ",") {
			if v, err := strconv.ParseUint(strings.TrimSpace(p), 16, 32); err == nil {
				ouiMap[uint32(v)] = vendor
			}
		}
	}
}

// Randomized reports a locally administered (privacy / random) MAC address.
func Randomized(mac string) bool {
	b, ok := firstOctet(mac)
	return ok && b&0x02 != 0
}

func firstOctet(mac string) (byte, bool) {
	h := strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac)
	if len(h) < 2 {
		return 0, false
	}
	v, err := strconv.ParseUint(h[:2], 16, 8)
	return byte(v), err == nil
}

// Vendor returns the manufacturer for a MAC address ("" when unknown).
func Vendor(mac string) string {
	if Randomized(mac) {
		return "Private address (randomized MAC)"
	}
	h := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(h) < 6 {
		return ""
	}
	v, err := strconv.ParseUint(h[:6], 16, 32)
	if err != nil {
		return ""
	}
	ouiOnce.Do(loadOUI)
	return ouiMap[uint32(v)]
}

// ParseARP reads the /proc/net/arp format into ip -> mac (complete entries only).
func ParseARP(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[2] == "0x0" || f[3] == "00:00:00:00:00:00" {
			continue
		}
		out[f[0]] = strings.ToLower(f[3])
	}
	return out
}

// ReadARP returns the host's ARP table (empty when not on Linux or not using host networking).
func ReadARP() map[string]string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return map[string]string{}
	}
	defer f.Close()
	return ParseARP(f)
}

type stat struct {
	first   int64
	last    atomic.Int64
	count   atomic.Int64
	flushed int64 // count already written (only touched by Flush)
	proto   atomic.Value
}

// Tracker counts queries per client address in memory and flushes them to the store every minute.
type Tracker struct {
	Store *store.Store
	Log   *slog.Logger
	// PTRResolver returns the LAN resolver for host-name lookups ("" = off).
	PTRResolver func() string
	ReadARP     func() map[string]string

	m       sync.Map // ip -> *stat
	n       atomic.Int64
	flushMu sync.Mutex
}

const maxTracked = 20000

// NewTracker creates a tracker.
func NewTracker(st *store.Store, log *slog.Logger, ptr func() string) *Tracker {
	return &Tracker{Store: st, Log: log, PTRResolver: ptr, ReadARP: ReadARP}
}

// Observe counts one query (cheap: no allocation for known clients).
func (t *Tracker) Observe(ip, proto string, now int64) {
	if t == nil || ip == "" {
		return
	}
	if v, ok := t.m.Load(ip); ok {
		s := v.(*stat)
		s.last.Store(now)
		s.count.Add(1)
		return
	}
	if t.n.Load() >= maxTracked {
		return
	}
	s := &stat{first: now}
	s.last.Store(now)
	s.proto.Store(proto)
	v, loaded := t.m.LoadOrStore(ip, s)
	if !loaded {
		t.n.Add(1)
	}
	v.(*stat).count.Add(1)
}

// Flush writes new counts to the store and forgets clients idle for an hour.
func (t *Tracker) Flush(now int64) {
	if t == nil {
		return
	}
	t.flushMu.Lock()
	defer t.flushMu.Unlock()
	var ds []store.ClientDelta
	t.m.Range(func(k, v any) bool {
		s := v.(*stat)
		c := s.count.Load()
		if delta := c - s.flushed; delta > 0 {
			proto, _ := s.proto.Load().(string)
			ds = append(ds, store.ClientDelta{IP: k.(string), First: s.first, Last: s.last.Load(), Queries: delta, Proto: proto})
			s.flushed = c
		} else if now-s.last.Load() > 3600 {
			t.m.Delete(k)
			t.n.Add(-1)
		}
		return true
	})
	if err := t.Store.UpsertClients(ds); err != nil && t.Log != nil {
		t.Log.Warn("client list update failed", "err", err)
	}
}

// Enrich looks up host names (reverse DNS on the local resolver) and MAC vendors for clients not
// checked in the last 6 hours.
func (t *Tracker) Enrich(ctx context.Context, now int64) {
	ips, err := t.Store.ClientsToEnrich(now-6*3600, 50)
	if err != nil || len(ips) == 0 {
		return
	}
	arp := t.ReadARP()
	resolver := ""
	if t.PTRResolver != nil {
		resolver = t.PTRResolver()
	}
	for _, ip := range ips {
		if ctx.Err() != nil {
			return
		}
		a, ok := netinfo.Parse(ip)
		host := ""
		if ok && netinfo.IsLAN(a) && !a.IsLoopback() && resolver != "" {
			host = ReverseLookup(ctx, resolver, a)
		}
		mac := arp[ip]
		vendor := ""
		if mac != "" {
			vendor = Vendor(mac)
		}
		_ = t.Store.SetClientInfo(ip, host, mac, vendor, now)
	}
}

// ReverseLookup asks resolver (host:port) for the PTR name of a.
func ReverseLookup(ctx context.Context, resolver string, a netip.Addr) string {
	rev, err := dns.ReverseAddr(a.String())
	if err != nil {
		return ""
	}
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(strings.Trim(resolver, "[]"), "53")
	}
	q := new(dns.Msg)
	q.SetQuestion(rev, dns.TypePTR)
	c := &dns.Client{Timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, _, err := c.ExchangeContext(ctx, q, resolver)
	if err != nil || r == nil {
		return ""
	}
	for _, rr := range r.Answer {
		if p, ok := rr.(*dns.PTR); ok {
			return strings.TrimSuffix(p.Ptr, ".")
		}
	}
	return ""
}

// Run flushes counts every minute and enriches clients every two minutes.
func (t *Tracker) Run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			t.Flush(time.Now().Unix())
			return
		case <-tick.C:
			now := time.Now().Unix()
			t.Flush(now)
			if n++; n%2 == 1 {
				t.Enrich(ctx, now)
			}
		}
	}
}
