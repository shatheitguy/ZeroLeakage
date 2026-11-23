// Package dnsserver answers DNS over UDP/TCP, DoT and DoH, applying ZeroLeakage policy.
package dnsserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/shatheitguy/ZeroLeakage/server/internal/clients"
	"github.com/shatheitguy/ZeroLeakage/server/internal/filter"
	"github.com/shatheitguy/ZeroLeakage/server/internal/guard"
	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
	"github.com/shatheitguy/ZeroLeakage/server/internal/netinfo"
	"github.com/shatheitguy/ZeroLeakage/server/internal/policy"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
	"github.com/shatheitguy/ZeroLeakage/server/internal/upstream"
)

// Client describes who sent a query.
type Client struct {
	IP       string // source address (no port)
	DeviceID string // from the DoH path or DoT SNI, if any
	Proto    string // udp, tcp, dot, doh
}

// Counters are cheap live totals since start.
type Counters struct {
	Queries atomic.Int64
	Blocked atomic.Int64
	Cached  atomic.Int64
	Errors  atomic.Int64
}

// state is an immutable snapshot built by Reload: the DNS hot path never touches the database.
type state struct {
	settings    store.Settings
	network     policy.Policy
	userPolicy  map[int64]policy.Policy
	devPolicy   map[string]policy.Policy
	compiled    map[string]*policy.Compiled // device id -> effective policy; "" = network default
	devices     map[string]store.Device
	byIP        map[string]string
	cidrs       []cidrDevice
	rewrites    *policy.Rewrites
	rewriteList []policy.Rewrite
	listsInUse  []string
}

type cidrDevice struct {
	net netip.Prefix
	id  string
}

// Engine holds the live policy and does the work for every listener.
type Engine struct {
	Lists    *lists.Manager
	Upstream *upstream.Client
	Store    *store.Store
	Log      *slog.Logger
	Guard    *guard.Guard     // optional
	Clients  *clients.Tracker // optional
	Now      func() time.Time
	Counters Counters
	Started  time.Time

	st       atomic.Pointer[state]
	self     map[netip.Addr]bool
	cache    *cache
	logCh    chan store.QueryEntry
	lastSeen sync.Map // device id -> unix seconds
}

func NewEngine(l *lists.Manager, up *upstream.Client, st *store.Store, log *slog.Logger) *Engine {
	e := &Engine{
		Lists: l, Upstream: up, Store: st, Log: log, Started: time.Now(), Now: time.Now,
		self:  map[netip.Addr]bool{},
		cache: newCache(20_000),
		logCh: make(chan store.QueryEntry, 4096),
	}
	for _, a := range netinfo.SelfAddrs() {
		e.self[a] = true
	}
	e.st.Store(&state{settings: store.DefaultSettings(nil), network: policy.DefaultNetwork(), compiled: map[string]*policy.Compiled{"": policy.Compile(policy.Input{Network: policy.DefaultNetwork()})},
		devices: map[string]store.Device{}, byIP: map[string]string{}, rewrites: policy.NewRewrites(nil)})
	return e
}

// SetSelf replaces the addresses treated as "this server" (tests).
func (e *Engine) SetSelf(addrs ...string) {
	e.self = map[netip.Addr]bool{}
	for _, s := range addrs {
		if a, ok := netinfo.Parse(s); ok {
			e.self[a] = true
		}
	}
}

func (e *Engine) isSelf(ip netip.Addr) bool { return ip.IsLoopback() || e.self[ip] }

// Settings returns a copy of the current server settings.
func (e *Engine) Settings() store.Settings { return e.st.Load().settings }

// NetworkPolicy is the admin's baseline policy.
func (e *Engine) NetworkPolicy() policy.Policy { return e.st.Load().network }

// UserPolicy returns a user's extras.
func (e *Engine) UserPolicy(id int64) (policy.Policy, bool) {
	p, ok := e.st.Load().userPolicy[id]
	return p, ok
}

// DevicePolicy returns a device's overrides.
func (e *Engine) DevicePolicy(id string) (policy.Policy, bool) {
	p, ok := e.st.Load().devPolicy[id]
	return p, ok
}

// Rewrites returns the local DNS records.
func (e *Engine) Rewrites() []policy.Rewrite {
	return append([]policy.Rewrite{}, e.st.Load().rewriteList...)
}

// Effective returns the compiled policy for a device ("" = network default).
func (e *Engine) Effective(deviceID string) *policy.Compiled {
	st := e.st.Load()
	if c, ok := st.compiled[deviceID]; ok {
		return c
	}
	return st.compiled[""]
}

// ListIDs is every filter list some policy needs (what Lists.Rebuild should load).
func (e *Engine) ListIDs() []string { return append([]string{}, e.st.Load().listsInUse...) }

// ClearCache drops cached upstream answers (after an upstream change).
func (e *Engine) ClearCache() { e.cache.clear() }

// Policy keys in the settings table.
const (
	NetworkPolicyKey = "policy:default"
	RewritesKey      = "rewrites"
)

// UserScope is the rule scope shared by every device a user owns.
func UserScope(userID int64) string { return "user:" + strconv.FormatInt(userID, 10) }

// Reload re-reads settings, policies, rules, devices and local records (call after any change).
func (e *Engine) Reload(settings store.Settings) error {
	network := policy.DefaultNetwork()
	if _, err := e.Store.GetJSON(NetworkPolicyKey, &network); err != nil {
		return err
	}
	raw, err := e.Store.JSONPrefix("policy:")
	if err != nil {
		return err
	}
	userPol, devPol := map[int64]policy.Policy{}, map[string]policy.Policy{}
	for k, v := range raw {
		var p policy.Policy
		if json.Unmarshal(v, &p) != nil {
			continue
		}
		switch {
		case strings.HasPrefix(k, "policy:user:"):
			if id, err := strconv.ParseInt(strings.TrimPrefix(k, "policy:user:"), 10, 64); err == nil {
				userPol[id] = p
			}
		case strings.HasPrefix(k, "policy:device:"):
			devPol[strings.TrimPrefix(k, "policy:device:")] = p
		}
	}
	var rws []policy.Rewrite
	if _, err := e.Store.GetJSON(RewritesKey, &rws); err != nil {
		return err
	}

	// Custom lists: the admin's (from the store) plus lists users added to their own policy.
	var custom []lists.List
	if cs, err := e.Store.CustomLists(); err == nil {
		for _, c := range cs {
			custom = append(custom, lists.List{ID: c.ID, Name: c.Name, URL: c.URL, Category: lists.NormalizeCategory(c.Category), Group: "Custom", Custom: true})
		}
	}
	for uid, p := range userPol {
		for _, c := range p.CustomLists {
			custom = append(custom, lists.List{ID: c.ID, Name: c.Name, URL: c.URL, Category: lists.NormalizeCategory(c.Category), Group: "User lists", Custom: true, Restricted: true, Owner: UserScope(uid)})
		}
	}
	e.Lists.SetCustom(custom)
	all := e.Lists.All()

	netAllow, netBlock, err := e.Store.RuleSets("default")
	if err != nil {
		return err
	}
	devs, err := e.Store.Devices(nil)
	if err != nil {
		return err
	}
	compiled := map[string]*policy.Compiled{"": policy.Compile(policy.Input{Network: network, NetworkLists: settings.EnabledLists, AllLists: all, NetAllow: netAllow, NetBlock: netBlock})}
	devices := map[string]store.Device{}
	byIP := map[string]string{}
	var cidrs []cidrDevice
	type rs struct{ allow, block map[string]bool }
	userRules := map[int64]rs{}
	for _, d := range devs {
		devices[d.ID] = d
		dA, dB, _ := e.Store.RuleSets("device:" + d.ID)
		in := policy.Input{Network: network, NetworkLists: settings.EnabledLists, AllLists: all, NetAllow: netAllow, NetBlock: netBlock, DeviceAllow: dA, DeviceBlock: dB}
		if p, ok := devPol[d.ID]; ok {
			in.Device = &p
		}
		if d.UserID != nil {
			ur, ok := userRules[*d.UserID]
			if !ok {
				uA, uB, _ := e.Store.RuleSets(UserScope(*d.UserID))
				ur = rs{uA, uB}
				userRules[*d.UserID] = ur
			}
			in.UserAllow, in.UserBlock = ur.allow, ur.block
			if p, ok := userPol[*d.UserID]; ok {
				in.User = &p
			}
		}
		compiled[d.ID] = policy.Compile(in)
		for _, ip := range d.IPs {
			if strings.Contains(ip, "/") {
				if p, ok := netinfo.ParsePrefix(ip); ok {
					cidrs = append(cidrs, cidrDevice{p, d.ID})
				}
			} else if a, ok := netinfo.Parse(ip); ok {
				byIP[a.String()] = d.ID
			}
		}
	}
	inUse := map[string]bool{}
	var ids []string
	for _, c := range compiled {
		for _, id := range c.ListsInUse() {
			if !inUse[id] {
				inUse[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	e.st.Store(&state{
		settings: settings, network: network, userPolicy: userPol, devPolicy: devPol, compiled: compiled,
		devices: devices, byIP: byIP, cidrs: cidrs, rewrites: policy.NewRewrites(rws), rewriteList: rws, listsInUse: ids,
	})
	return nil
}

func (st *state) identify(c Client) (string, *store.Device) {
	if c.DeviceID != "" {
		if d, ok := st.devices[c.DeviceID]; ok {
			return d.ID, &d
		}
	}
	if id, ok := st.byIP[c.IP]; ok {
		d := st.devices[id]
		return id, &d
	}
	if len(st.cidrs) > 0 {
		if ip, ok := netinfo.Parse(c.IP); ok {
			for _, cd := range st.cidrs {
				if cd.net.Contains(ip) {
					d := st.devices[cd.id]
					return cd.id, &d
				}
			}
		}
	}
	return "", nil
}

// DeviceForIP returns the device id mapped to a client address ("" when none).
func (e *Engine) DeviceForIP(ip string) string {
	id, _ := e.st.Load().identify(Client{IP: ip})
	return id
}

// Decision is the outcome for one query (also used by the dashboard's "check domain").
type Decision struct {
	Blocked    bool             `json:"blocked"`
	Reason     string           `json:"reason"`
	Match      *filter.Match    `json:"match,omitempty"`
	Service    string           `json:"service,omitempty"`  // service id the domain belongs to
	Category   string           `json:"category,omitempty"` // category id of a list that lists the domain
	Local      []policy.Rewrite `json:"local,omitempty"`    // answered from local records
	PTR        string           `json:"ptr,omitempty"`      // local reverse record
	SafeSearch string           `json:"safeSearch,omitempty"`
	trusted    bool             // paused or allowlisted: skip answer checks
}

// Decide applies the policy for a device ("" = default) to a domain (A query, no client address).
func (e *Engine) Decide(deviceID, domain string) Decision {
	return e.DecideFor(deviceID, "", domain, dns.TypeA)
}

// DecideFor is Decide with the client's address (bypass blocking applies to LAN clients) and query type.
func (e *Engine) DecideFor(deviceID, clientIP, domain string, qtype uint16) Decision {
	st := e.st.Load()
	ip, _ := netinfo.Parse(clientIP)
	return e.decide(st, deviceID, ip, strings.ToLower(strings.TrimSuffix(domain, ".")), qtype, e.Now())
}

func (e *Engine) decide(st *state, devID string, ip netip.Addr, name string, qtype uint16, now time.Time) Decision {
	pol, ok := st.compiled[devID]
	if !ok {
		pol, devID = st.compiled[""], ""
	}
	if d, ok := st.devices[devID]; ok && d.Paused {
		return Decision{Reason: "Protection paused for this device", trusted: true}
	}
	svc := policy.LookupServices(name)
	dec := Decision{}
	if s, ok := policy.FirstService(svc); ok {
		dec.Service = s.ID
	}
	if name == "use-application-dns.net" { // Firefox canary: keep browsers on this server's filtering
		dec.Blocked, dec.Reason = true, "DoH canary"
		return dec
	}
	idx := e.Lists.Index()
	n := pol.At(now, idx)
	if n.BlockAll != nil && !n.BlockAllAllows(name) {
		dec.Blocked, dec.Reason = true, "Schedule: "+n.BlockAll.Name
		return dec
	}
	if !st.rewrites.Empty() {
		if qtype == dns.TypePTR {
			if h, ok := st.rewrites.PTR(name); ok {
				dec.PTR, dec.Reason = h, "Local record"
				return dec
			}
		}
		if rs := st.rewrites.Lookup(name); rs != nil {
			dec.Local, dec.Reason = rs, "Local record"
			return dec
		}
	}
	// Network rules: admin's block beats every allow.
	netMatch := filter.MatchUser(name, pol.NetAllow, pol.NetBlock)
	if netMatch != nil && netMatch.Blocked {
		netMatch.ListName, netMatch.Category = "Network blocklist", "Network blocklist"
		dec.Blocked, dec.Reason, dec.Match = true, "Network blocklist", netMatch
		return dec
	}
	if target, engine := policy.SafeTarget(name, pol.SafeSearch); target != "" {
		dec.SafeSearch, dec.Reason = target, "SafeSearch ("+engine+")"
		return dec
	}
	if netMatch != nil { // network allow
		netMatch.ListName = "Network allowlist"
		dec.Reason, dec.Match, dec.trusted = "Allowlisted", netMatch, true
		return dec
	}
	mode := st.settings.BlockBypass
	if mode == policy.BypassAll || (mode != policy.BypassOff && ip.IsValid() && netinfo.IsLAN(ip)) {
		if !(ip.IsValid() && e.isSelf(ip)) { // the server's own lookups are never affected
			if p, ok := policy.BypassProvider(name); ok {
				dec.Blocked, dec.Reason = true, "Filtering bypass: "+p
				return dec
			}
		}
	}
	if m := svc & n.BaseServices; m != 0 {
		return serviceBlock(dec, m, n)
	}
	lm, seen := idx.MatchLists(name, n.BaseLists)
	dec.Category, _ = idx.CategoryOf(seen)
	if lm != nil {
		if lm.Blocked {
			dec.Blocked, dec.Reason, dec.Match, dec.Category = true, lm.Category, lm, lm.CategoryID
			if n.FromSchedule(0, idx.Bit(lm.ListID)) {
				dec.Reason = "Schedule " + n.Schedule + ": " + lm.Category
			}
			return dec
		}
		dec.Reason, dec.Match = lm.Category, lm
		return dec
	}
	// The owner's and the device's own rules and additions.
	if um := filter.MatchUser(name, pol.Allow, pol.Block); um != nil {
		dec.Match = um
		if um.Blocked {
			dec.Blocked, dec.Reason = true, um.Category
		} else {
			dec.Reason, dec.trusted = um.Category, true
		}
		return dec
	}
	if m := svc & n.ExtraServices; m != 0 {
		return serviceBlock(dec, m, n)
	}
	if n.ExtraLists != 0 {
		if lm, _ := idx.MatchLists(name, n.ExtraLists); lm != nil {
			if lm.Blocked {
				dec.Blocked, dec.Reason, dec.Match, dec.Category = true, lm.Category, lm, lm.CategoryID
				return dec
			}
			dec.Reason, dec.Match = lm.Category, lm
			return dec
		}
	}
	dec.Reason = "No rule"
	return dec
}

func serviceBlock(dec Decision, m uint64, n policy.Now) Decision {
	s, _ := policy.FirstService(m)
	dec.Blocked, dec.Service = true, s.ID
	dec.Reason = "Blocked service: " + s.Name
	if n.FromSchedule(m, 0) {
		dec.Reason = "Schedule " + n.Schedule + ": " + s.Name
	}
	return dec
}

// Handle answers one DNS message for a client.
func (e *Engine) Handle(ctx context.Context, req *dns.Msg, c Client) *dns.Msg {
	e.Counters.Queries.Add(1)
	began := time.Now()
	start := e.Now()
	if len(req.Question) != 1 {
		return refuse(req, dns.RcodeFormatError)
	}
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	st := e.st.Load()
	devID, _ := st.identify(c)
	if devID != "" {
		e.lastSeen.Store(devID, start.Unix())
	}
	ip, _ := netinfo.Parse(c.IP)
	self := ip.IsValid() && e.isSelf(ip)
	if !self {
		e.Clients.Observe(c.IP, c.Proto, start.Unix())
	}
	entry := store.QueryEntry{TS: start.UnixMilli(), Client: c.IP, DeviceID: devID, QName: name, QType: dns.TypeToString[q.Qtype]}
	resp := e.handle(ctx, req, st, devID, ip, self, name, q.Qtype, start, &entry)
	entry.LatencyMs = time.Since(began).Milliseconds()
	entry.RCode = dns.RcodeToString[resp.Rcode]
	if entry.Blocked {
		e.Counters.Blocked.Add(1)
	}
	if st.settings.LogQueries {
		select {
		case e.logCh <- entry:
		default: // never block DNS on logging
		}
	}
	return resp
}

func (e *Engine) handle(ctx context.Context, req *dns.Msg, st *state, devID string, ip netip.Addr, self bool, name string, qtype uint16, now time.Time, entry *store.QueryEntry) *dns.Msg {
	g := e.Guard
	guardOn := g.Enabled() && ip.IsValid() && !self
	if guardOn {
		g.ObserveQuery(ip, devID, name, qtype)
		if ban := g.Banned(ip); ban != nil {
			if g.Effect(ip) == guard.EffectRefuse {
				entry.Blocked, entry.Reason = true, "Guard ban: "+ban.Reason
				return refuse(req, dns.RcodeRefused)
			}
			if !g.QuarantineAllows(name, st.settings.PublicHostname) {
				entry.Blocked, entry.Reason = true, "Quarantined: "+ban.Reason
				return e.blocked(req, st)
			}
		}
	}
	dec := e.decide(st, devID, ip, name, qtype, now)
	entry.Service, entry.Category = dec.Service, dec.Category
	switch {
	case dec.Blocked:
		entry.Blocked, entry.Reason = true, dec.Reason
		if dec.Match != nil {
			entry.List = dec.Match.ListName
		}
		if guardOn && dec.Category == "malware" {
			g.ObserveMalware(ip, devID, name)
		}
		return e.blocked(req, st)
	case dec.PTR != "":
		entry.Reason, entry.Upstream = dec.Reason, "local"
		m := reply(req)
		m.Authoritative = true
		m.Answer = []dns.RR{&dns.PTR{Hdr: hdr(req.Question[0].Name, dns.TypePTR, 300), Ptr: dns.Fqdn(dec.PTR)}}
		return m
	case dec.Local != nil:
		entry.Reason, entry.Upstream = dec.Reason, "local"
		return e.answerLocal(ctx, req, st, dec.Local, 0)
	case dec.SafeSearch != "":
		entry.Reason, entry.Upstream = dec.Reason, "safesearch"
		m := reply(req)
		cname := &dns.CNAME{Hdr: hdr(req.Question[0].Name, dns.TypeCNAME, 300), Target: dns.Fqdn(dec.SafeSearch)}
		ans, _, err := e.resolve(ctx, question(dec.SafeSearch, qtype))
		if err != nil {
			entry.Reason = "Upstream error"
			e.Counters.Errors.Add(1)
			return refuse(req, dns.RcodeServerFailure)
		}
		m.Answer = append([]dns.RR{cname}, ans.Answer...)
		m.Rcode = ans.Rcode
		return m
	}
	resp, from, err := e.resolve(ctx, req)
	if err != nil {
		e.Counters.Errors.Add(1)
		e.Log.Debug("upstream failed", "name", name, "err", err)
		entry.Reason = "Upstream error"
		return refuse(req, dns.RcodeServerFailure)
	}
	entry.Upstream, entry.Reason = from, dec.Reason
	if !dec.trusted {
		// CNAME cloaking: a tracker hidden behind a first-party name.
		if bd := e.cnameBlocked(st, devID, ip, resp, now); bd != nil {
			entry.Blocked, entry.Reason = true, "CNAME cloaking ("+bd.Reason+")"
			if bd.Match != nil {
				entry.List = bd.Match.ListName
			}
			if bd.Service != "" {
				entry.Service = bd.Service
			}
			return e.blocked(req, st)
		}
		// Guard: an answer pointing at a known-bad address (botnet C2, hijacked netblocks).
		if g.Enabled() {
			for _, rr := range resp.Answer {
				var a netip.Addr
				switch v := rr.(type) {
				case *dns.A:
					a, _ = netip.AddrFromSlice(v.A.To4())
				case *dns.AAAA:
					a, _ = netip.AddrFromSlice(v.AAAA)
				default:
					continue
				}
				if feeds := g.ThreatIP(a); feeds != nil {
					g.Stats.ThreatAnswers.Add(1)
					entry.Blocked, entry.Reason, entry.List, entry.Category = true, "Malicious IP "+a.String(), strings.Join(feeds, ", "), "malware"
					if guardOn {
						g.ObserveMalware(ip, devID, name)
					}
					return e.blocked(req, st)
				}
			}
		}
	}
	if guardOn {
		g.ObserveAnswer(ip, devID, name, resp.Rcode)
	}
	return resp
}

// resolve answers from the cache or the upstream (answers are cached as received: policy is
// applied on top for every client, so one device's allowlist never leaks to another).
func (e *Engine) resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	if cached := e.cache.get(req); cached != nil {
		e.Counters.Cached.Add(1)
		return cached, "cache", nil
	}
	ans, err := e.Upstream.Exchange(ctx, req)
	if err != nil {
		return nil, "", err
	}
	e.cache.put(req, ans.Msg)
	return ans.Msg, ans.Resolver, nil
}

func (e *Engine) cnameBlocked(st *state, devID string, ip netip.Addr, m *dns.Msg, now time.Time) *Decision {
	for _, rr := range m.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			target := strings.ToLower(strings.TrimSuffix(c.Target, "."))
			if d := e.decide(st, devID, ip, target, dns.TypeA, now); d.Blocked && (d.Match != nil || d.Service != "") {
				if d.Match != nil {
					d.Reason = d.Match.Matched
				}
				return &d
			}
		}
	}
	return nil
}

// answerLocal answers from local records; a CNAME is followed locally, then upstream.
func (e *Engine) answerLocal(ctx context.Context, req *dns.Msg, st *state, rs []policy.Rewrite, depth int) *dns.Msg {
	q := req.Question[0]
	m := reply(req)
	m.Authoritative = true
	for _, r := range rs {
		if r.Type != "CNAME" {
			continue
		}
		m.Answer = append(m.Answer, &dns.CNAME{Hdr: hdr(q.Name, dns.TypeCNAME, 300), Target: dns.Fqdn(r.Value)})
		if q.Qtype == dns.TypeCNAME {
			return m
		}
		if next := st.rewrites.Lookup(r.Value); next != nil && depth < 5 {
			sub := e.answerLocal(ctx, question(r.Value, q.Qtype), st, next, depth+1)
			m.Answer = append(m.Answer, sub.Answer...)
			return m
		}
		ans, _, err := e.resolve(ctx, question(r.Value, q.Qtype))
		if err == nil {
			m.Answer = append(m.Answer, ans.Answer...)
			m.Rcode = ans.Rcode
		}
		return m
	}
	for _, r := range rs {
		switch {
		case r.Type == "A" && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr(q.Name, dns.TypeA, 300), A: net.ParseIP(r.Value).To4()})
		case r.Type == "AAAA" && q.Qtype == dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr(q.Name, dns.TypeAAAA, 300), AAAA: net.ParseIP(r.Value)})
		}
	}
	return m // other types: NOERROR with no data, so nothing leaks to the upstream
}

func question(name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	return q
}

func reply(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	return m
}

func hdr(name string, t uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
}

func (e *Engine) blocked(req *dns.Msg, st *state) *dns.Msg {
	m := reply(req)
	q := req.Question[0]
	if st.settings.BlockMode == "null_ip" && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) {
		if q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: hdr(q.Name, dns.TypeA, 60), A: net.IPv4zero}}
		} else {
			m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr(q.Name, dns.TypeAAAA, 60), AAAA: net.IPv6zero}}
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
			e.Store.Prune(e.Settings().RetentionDays)
			go e.Lists.Rebuild(context.Background(), e.ListIDs(), 24*time.Hour)
		}
	}
}

// FlushLog writes queued query-log entries now (tests).
func (e *Engine) FlushLog() {
	var batch []store.QueryEntry
	for {
		select {
		case q := <-e.logCh:
			batch = append(batch, q)
		default:
			_ = e.Store.InsertQueries(batch)
			return
		}
	}
}
