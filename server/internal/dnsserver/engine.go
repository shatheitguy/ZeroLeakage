// Package dnsserver answers DNS over UDP/TCP, DoT and DoH, applying ZeroLeakage policy.
package dnsserver

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/shatheitguy/ZeroLeakage/server/internal/filter"
	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
	"github.com/shatheitguy/ZeroLeakage/server/internal/upstream"
)

// Client describes who sent a query.
type Client struct {
	IP       string // source address (no port)
	DeviceID string // from the DoH path or DoT SNI, if any
	Proto    string // udp, tcp, dot, doh
}

type ruleSet struct{ allow, block map[string]bool }

func (r ruleSet) merged(others ...ruleSet) ruleSet {
	out := ruleSet{map[string]bool{}, map[string]bool{}}
	for _, s := range append([]ruleSet{r}, others...) {
		for k := range s.allow {
			out.allow[k] = true
		}
		for k := range s.block {
			out.block[k] = true
		}
	}
	return out
}

// Counters are cheap live totals since start.
type Counters struct {
	Queries atomic.Int64
	Blocked atomic.Int64
	Cached  atomic.Int64
	Errors  atomic.Int64
}

// Engine holds the live policy and does the work for every listener.
type Engine struct {
	Lists    *lists.Manager
	Upstream *upstream.Client
	Store    *store.Store
	Log      *slog.Logger
	Counters Counters
	Started  time.Time

	mu       sync.RWMutex
	settings store.Settings
	rules    map[string]ruleSet // effective rules per device id; "" = default
	devices  map[string]store.Device
	byIP     map[string]string // client IP -> device id
	cidrs    []cidrDevice

	cache    *cache
	logCh    chan store.QueryEntry
	lastSeen sync.Map // device id -> unix seconds
}

type cidrDevice struct {
	net *net.IPNet
	id  string
}

func NewEngine(l *lists.Manager, up *upstream.Client, st *store.Store, log *slog.Logger) *Engine {
	return &Engine{
		Lists: l, Upstream: up, Store: st, Log: log, Started: time.Now(),
		rules: map[string]ruleSet{}, devices: map[string]store.Device{}, byIP: map[string]string{},
		cache: newCache(20_000),
		logCh: make(chan store.QueryEntry, 4096),
	}
}

// Settings returns a copy of the current server settings.
func (e *Engine) Settings() store.Settings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.settings
}

// Reload re-reads settings, rules and devices from the store (call after any change).
func (e *Engine) Reload(st store.Settings) error {
	defAllow, defBlock, err := e.Store.RuleSets("default")
	if err != nil {
		return err
	}
	def := ruleSet{defAllow, defBlock}
	devs, err := e.Store.Devices(nil)
	if err != nil {
		return err
	}
	rules := map[string]ruleSet{"": def}
	devices := map[string]store.Device{}
	byIP := map[string]string{}
	var cidrs []cidrDevice
	userRules := map[int64]ruleSet{}
	for _, d := range devs {
		devices[d.ID] = d
		dA, dB, _ := e.Store.RuleSets("device:" + d.ID)
		rs := def.merged(ruleSet{dA, dB})
		if d.UserID != nil {
			ur, ok := userRules[*d.UserID]
			if !ok {
				uA, uB, _ := e.Store.RuleSets(UserScope(*d.UserID))
				ur = ruleSet{uA, uB}
				userRules[*d.UserID] = ur
			}
			rs = rs.merged(ur)
		}
		rules[d.ID] = rs
		for _, ip := range d.IPs {
			if strings.Contains(ip, "/") {
				if _, n, err := net.ParseCIDR(ip); err == nil {
					cidrs = append(cidrs, cidrDevice{n, d.ID})
				}
			} else if p := net.ParseIP(ip); p != nil {
				byIP[p.String()] = d.ID
			}
		}
	}
	e.mu.Lock()
	e.settings, e.rules, e.devices, e.byIP, e.cidrs = st, rules, devices, byIP, cidrs
	e.mu.Unlock()
	e.cache.clear()
	return nil
}

// UserScope is the rule scope shared by every device a user owns.
func UserScope(userID int64) string { return "user:" + itoa(userID) }

func (e *Engine) identify(c Client) (string, *store.Device) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if c.DeviceID != "" {
		if d, ok := e.devices[c.DeviceID]; ok {
			return d.ID, &d
		}
	}
	if id, ok := e.byIP[c.IP]; ok {
		d := e.devices[id]
		return id, &d
	}
	if ip := net.ParseIP(c.IP); ip != nil {
		for _, cd := range e.cidrs {
			if cd.net.Contains(ip) {
				d := e.devices[cd.id]
				return cd.id, &d
			}
		}
	}
	return "", nil
}

// Decision is the outcome for one query (also used by the dashboard's "check domain").
type Decision struct {
	Blocked bool          `json:"blocked"`
	Reason  string        `json:"reason"`
	Match   *filter.Match `json:"match,omitempty"`
}

// Decide applies the policy for a device ("" = default) to a domain.
func (e *Engine) Decide(deviceID, domain string) Decision {
	e.mu.RLock()
	rs, ok := e.rules[deviceID]
	if !ok {
		rs = e.rules[""]
	}
	paused := false
	if d, ok := e.devices[deviceID]; ok {
		paused = d.Paused
	}
	e.mu.RUnlock()
	if paused {
		return Decision{Reason: "Protection paused for this device"}
	}
	if domain == "use-application-dns.net" { // Firefox canary: keep browsers on this server's filtering
		return Decision{Blocked: true, Reason: "DoH canary"}
	}
	m := e.Lists.Index().Match(domain, rs.allow, rs.block)
	if m == nil {
		return Decision{Reason: "No rule"}
	}
	if m.Blocked {
		return Decision{Blocked: true, Reason: m.Category, Match: m}
	}
	return Decision{Reason: m.Category, Match: m}
}

// Handle answers one DNS message for a client.
func (e *Engine) Handle(ctx context.Context, req *dns.Msg, c Client) *dns.Msg {
	e.Counters.Queries.Add(1)
	start := time.Now()
	if len(req.Question) != 1 {
		return refuse(req, dns.RcodeFormatError)
	}
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	devID, _ := e.identify(c)
	if devID != "" {
		e.lastSeen.Store(devID, time.Now().Unix())
	}
	entry := store.QueryEntry{TS: start.UnixMilli(), Client: c.IP, DeviceID: devID, QName: name, QType: dns.TypeToString[q.Qtype]}

	dec := e.Decide(devID, name)
	var resp *dns.Msg
	if dec.Blocked {
		resp = e.blocked(req)
		entry.Blocked, entry.Reason = true, dec.Reason
		if dec.Match != nil {
			entry.List = dec.Match.ListName
		}
		e.Counters.Blocked.Add(1)
	} else if cached := e.cache.get(req); cached != nil {
		resp = cached
		entry.Reason, entry.Upstream = "Cached", "cache"
		e.Counters.Cached.Add(1)
	} else {
		ans, err := e.Upstream.Exchange(ctx, req)
		if err != nil {
			e.Counters.Errors.Add(1)
			e.Log.Debug("upstream failed", "name", name, "err", err)
			resp = refuse(req, dns.RcodeServerFailure)
			entry.Reason = "Upstream error"
		} else {
			resp = ans.Msg
			entry.Upstream = ans.Resolver
			entry.Reason = dec.Reason
			// CNAME cloaking: a tracker hidden behind a first-party name.
			if blockedBy := e.cnameBlocked(devID, resp); blockedBy != nil {
				resp = e.blocked(req)
				entry.Blocked, entry.Reason, entry.List = true, "CNAME cloaking ("+blockedBy.Matched+")", blockedBy.ListName
				e.Counters.Blocked.Add(1)
			} else {
				e.cache.put(req, resp)
			}
		}
	}
	entry.LatencyMs = time.Since(start).Milliseconds()
	entry.RCode = dns.RcodeToString[resp.Rcode]
	if e.Settings().LogQueries {
		select {
		case e.logCh <- entry:
		default: // never block DNS on logging
		}
	}
	return resp
}

func (e *Engine) cnameBlocked(devID string, m *dns.Msg) *filter.Match {
	for _, rr := range m.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			target := strings.TrimSuffix(c.Target, ".")
			if d := e.Decide(devID, target); d.Blocked && d.Match != nil {
				return d.Match
			}
		}
	}
	return nil
}

func (e *Engine) blocked(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	q := req.Question[0]
	if e.Settings().BlockMode == "null_ip" && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) {
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
		if q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero}}
		} else {
			m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero}}
		}
		return m
	}
	m.Rcode = dns.RcodeNameError
	return m
}

func refuse(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true
	return m
}

// RunBackground writes the query log, refreshes lists daily and prunes old rows.
func (e *Engine) RunBackground(ctx context.Context) {
	flush := time.NewTicker(time.Second)
	daily := time.NewTicker(24 * time.Hour)
	seen := time.NewTicker(time.Minute)
	defer flush.Stop()
	defer daily.Stop()
	defer seen.Stop()
	var batch []store.QueryEntry
	for {
		select {
		case <-ctx.Done():
			_ = e.Store.InsertQueries(batch)
			return
		case q := <-e.logCh:
			batch = append(batch, q)
			if len(batch) >= 500 {
				_ = e.Store.InsertQueries(batch)
				batch = batch[:0]
			}
		case <-flush.C:
			if len(batch) > 0 {
				if err := e.Store.InsertQueries(batch); err != nil {
					e.Log.Warn("query log write failed", "err", err)
				}
				batch = batch[:0]
			}
		case <-seen.C:
			m := map[string]int64{}
			e.lastSeen.Range(func(k, v any) bool { m[k.(string)] = v.(int64); return true })
			e.Store.TouchDevices(m)
		case <-daily.C:
			st := e.Settings()
			e.Store.Prune(st.RetentionDays)
			go e.Lists.Rebuild(context.Background(), st.EnabledLists, 24*time.Hour)
		}
	}
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
