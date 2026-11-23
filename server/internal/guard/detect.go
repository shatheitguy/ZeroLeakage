package guard

import (
	"fmt"
	"hash/fnv"
	"math"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
)

// clientState holds tumbling-window counters for one client address. Memory per client is bounded.
type clientState struct {
	mu       sync.Mutex
	lastSeen int64

	floodStart int64
	floodCount int

	nxStart int64
	nxNames map[uint64]struct{}

	tunStart   int64
	tunParents map[string]*tunStat

	malStart int64
	malCount int

	authStart int64
	authCount int

	fired map[string]int64 // scenario -> unix seconds of the last alert (cool-down = window)
}

type tunStat struct {
	unique     map[uint64]struct{}
	suspicious int
}

const (
	maxNXNames      = 4096
	maxTunParents   = 64
	maxTunPerParent = 4096
)

func (g *Guard) state(ip string) *clientState {
	if v, ok := g.states.Load(ip); ok {
		return v.(*clientState)
	}
	v, _ := g.states.LoadOrStore(ip, &clientState{fired: map[string]int64{}})
	return v.(*clientState)
}

func (g *Guard) sweepStates() {
	cut := g.Now().Unix() - 3600
	g.states.Range(func(k, v any) bool {
		st := v.(*clientState)
		st.mu.Lock()
		idle := st.lastSeen < cut
		st.mu.Unlock()
		if idle {
			g.states.Delete(k)
		}
		return true
	})
}

// window resets a tumbling window when it has elapsed; returns true when it was reset.
func window(start *int64, now int64, sec int) bool {
	if now-*start >= int64(sec) {
		*start = now
		return true
	}
	return false
}

type trigger struct {
	id  string
	sc  Scenario
	msg string
}

// shouldFire applies the per-scenario cool-down (one alert per window per client).
func (st *clientState) shouldFire(id string, now int64, sc Scenario) bool {
	if last, ok := st.fired[id]; ok && now-last < int64(sc.WindowSec) {
		return false
	}
	st.fired[id] = now
	return true
}

func hash(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

func (g *Guard) tracked(ip netip.Addr) bool {
	return g != nil && ip.IsValid() && g.cfg.Load().Enabled
}

// ObserveQuery feeds one query into the flood and tunnelling detectors.
func (g *Guard) ObserveQuery(ip netip.Addr, deviceID, name string, qtype uint16) {
	if !g.tracked(ip) {
		return
	}
	rc := g.cfg.Load()
	key := ip.Unmap().String()
	st := g.state(key)
	now := g.Now().Unix()
	var fire []trigger

	st.mu.Lock()
	st.lastSeen = now
	if sc := rc.Flood; sc.Enabled {
		if window(&st.floodStart, now, sc.WindowSec) {
			st.floodCount = 0
		}
		st.floodCount++
		if st.floodCount >= sc.Threshold*sc.WindowSec && st.shouldFire(ScenarioFlood, now, sc) {
			fire = append(fire, trigger{ScenarioFlood, sc, fmt.Sprintf("Query flood: %d queries in %ds (limit %d/s)", st.floodCount, sc.WindowSec, sc.Threshold)})
		}
	}
	if sc := rc.Tunnel; sc.Enabled {
		if sub, parent := splitParent(name); sub != "" {
			if window(&st.tunStart, now, sc.WindowSec) || st.tunParents == nil {
				st.tunParents = map[string]*tunStat{}
			}
			ts := st.tunParents[parent]
			if ts == nil && len(st.tunParents) < maxTunParents {
				ts = &tunStat{unique: map[uint64]struct{}{}}
				st.tunParents[parent] = ts
			}
			if ts != nil && len(ts.unique) < maxTunPerParent {
				h := hash(sub)
				if _, dup := ts.unique[h]; !dup {
					ts.unique[h] = struct{}{}
					if suspiciousLabel(sub, qtype) {
						ts.suspicious++
					}
					if len(ts.unique) >= sc.Threshold && ts.suspicious*2 >= len(ts.unique) && st.shouldFire(ScenarioTunnel+":"+parent, now, sc) {
						fire = append(fire, trigger{ScenarioTunnel, sc, fmt.Sprintf("Possible DNS tunnelling: %d random-looking subdomains of %s in %ds", len(ts.unique), parent, sc.WindowSec)})
					}
				}
			}
		}
	}
	st.mu.Unlock()
	g.fire(ip, deviceID, fire)
}

// ObserveAnswer feeds an upstream answer into the NXDOMAIN-storm detector (DGA malware indicator).
func (g *Guard) ObserveAnswer(ip netip.Addr, deviceID, name string, rcode int) {
	if rcode != dns.RcodeNameError || !g.tracked(ip) {
		return
	}
	sc := g.cfg.Load().NXDomain
	if !sc.Enabled {
		return
	}
	st := g.state(ip.Unmap().String())
	now := g.Now().Unix()
	var fire []trigger
	st.mu.Lock()
	st.lastSeen = now
	if window(&st.nxStart, now, sc.WindowSec) || st.nxNames == nil {
		st.nxNames = map[uint64]struct{}{}
	}
	if len(st.nxNames) < maxNXNames {
		st.nxNames[hash(name)] = struct{}{}
	}
	if len(st.nxNames) >= sc.Threshold && st.shouldFire(ScenarioNXDomain, now, sc) {
		fire = append(fire, trigger{ScenarioNXDomain, sc, fmt.Sprintf("NXDOMAIN storm: %d non-existent names in %ds (possible DGA malware)", len(st.nxNames), sc.WindowSec)})
	}
	st.mu.Unlock()
	g.fire(ip, deviceID, fire)
}

// ObserveMalware records a blocked malware/phishing lookup or an answer pointing at a threat IP.
func (g *Guard) ObserveMalware(ip netip.Addr, deviceID, name string) {
	if !g.tracked(ip) {
		return
	}
	sc := g.cfg.Load().Malware
	if !sc.Enabled {
		return
	}
	st := g.state(ip.Unmap().String())
	now := g.Now().Unix()
	var fire []trigger
	st.mu.Lock()
	st.lastSeen = now
	if window(&st.malStart, now, sc.WindowSec) {
		st.malCount = 0
	}
	st.malCount++
	if st.malCount >= sc.Threshold && st.shouldFire(ScenarioMalware, now, sc) {
		fire = append(fire, trigger{ScenarioMalware, sc, fmt.Sprintf("Possibly infected device: %d malware/phishing lookups in %d min (latest %s)", st.malCount, sc.WindowSec/60, name)})
	}
	st.mu.Unlock()
	g.fire(ip, deviceID, fire)
}

// LoginFailure records a failed dashboard / app sign-in from ip.
func (g *Guard) LoginFailure(ip netip.Addr) {
	if !g.tracked(ip) {
		return
	}
	sc := g.cfg.Load().BruteForce
	if !sc.Enabled {
		return
	}
	st := g.state(ip.Unmap().String())
	now := g.Now().Unix()
	var fire []trigger
	st.mu.Lock()
	st.lastSeen = now
	if window(&st.authStart, now, sc.WindowSec) {
		st.authCount = 0
	}
	st.authCount++
	if st.authCount >= sc.Threshold && st.shouldFire(ScenarioBruteForce, now, sc) {
		fire = append(fire, trigger{ScenarioBruteForce, sc, fmt.Sprintf("Sign-in brute force: %d failed sign-ins in %d min", st.authCount, sc.WindowSec/60)})
	}
	st.mu.Unlock()
	g.fire(ip, "", fire)
}

// fire turns triggers into alerts and, when configured, bans.
func (g *Guard) fire(ip netip.Addr, devID string, ts []trigger) {
	for _, t := range ts {
		a := store.Alert{IP: ip.Unmap().String(), DeviceID: devID, Scenario: t.id, Message: t.msg, Action: "alert"}
		if t.sc.Action == "ban" {
			if _, err := g.Ban(a.IP, t.id, t.msg, "auto", t.sc.BanMinutes); err == nil {
				a.Action = "ban"
				a.Message += fmt.Sprintf(" - banned for %d min", t.sc.BanMinutes)
			} else if err == ErrNeverBan {
				a.Message += " - not banned (never-ban list)"
			} else {
				g.Log.Warn("guard ban failed", "ip", a.IP, "err", err)
			}
		}
		g.Log.Info("guard alert", "ip", a.IP, "scenario", a.Scenario, "action", a.Action, "message", a.Message)
		g.RecordAlert(a)
	}
}

// twoLevelSLD are second-level labels under ccTLDs that act like TLDs (co.uk, com.au …).
var twoLevelSLD = map[string]bool{"co": true, "com": true, "net": true, "org": true, "gov": true, "ac": true, "edu": true, "or": true, "ne": true, "go": true}

// splitParent splits "abc.def.example.co.uk" into ("abc.def", "example.co.uk").
func splitParent(name string) (sub, parent string) {
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	n := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && twoLevelSLD[labels[len(labels)-2]] {
		n = 3
	}
	if len(labels) <= n {
		return "", name
	}
	return strings.Join(labels[:len(labels)-n], "."), strings.Join(labels[len(labels)-n:], ".")
}

// suspiciousLabel: long or high-entropy subdomains, or TXT/NULL lookups (classic tunnel carriers).
func suspiciousLabel(sub string, qtype uint16) bool {
	if qtype == dns.TypeTXT || qtype == dns.TypeNULL {
		return true
	}
	longest := 0
	for _, l := range strings.Split(sub, ".") {
		longest = max(longest, len(l))
	}
	if longest >= 40 || len(sub) >= 60 {
		return true
	}
	flat := strings.ReplaceAll(sub, ".", "")
	return len(flat) >= 20 && entropy(flat) >= 3.8
}

// entropy is the Shannon entropy in bits per character.
func entropy(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
