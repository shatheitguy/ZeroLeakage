// Package policy holds what a network, a user or a device asks the server to block: one-click
// services, web categories, SafeSearch, schedules and local DNS records, plus the logic that merges
// them. The admin's network policy is the baseline; users and devices can only add to it.
package policy

import (
	"errors"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/filter"
	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
)

// CustomList is a list a user added to their own policy by URL (fetched over https from public hosts only).
type CustomList struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Category string `json:"category"`
}

// Policy is what one scope asks for. For the network, enabled filter lists live in the server settings
// (EnabledLists) and Lists here is unused.
type Policy struct {
	Lists       []string     `json:"lists"`
	CustomLists []CustomList `json:"customLists,omitempty"`
	Services    []string     `json:"services"`
	Categories  []string     `json:"categories"`
	SafeSearch  SafeSearch   `json:"safeSearch"`
	Schedules   []Schedule   `json:"schedules"`
	UpdatedAt   int64        `json:"updatedAt,omitempty"` // unix millis, for last-writer-wins sync
}

// DefaultNetwork is the out-of-the-box network policy: privacy and security categories on.
func DefaultNetwork() Policy {
	return Policy{Lists: []string{}, Services: []string{}, Categories: lists.DefaultCategories(), SafeSearch: SafeSearch{YouTube: YouTubeOff}, Schedules: []Schedule{}}
}

const maxCustomLists = 20

// Normalize drops unknown ids, de-duplicates, validates schedules and custom lists.
// knownList reports whether a list id exists. allowSchedules=false strips schedules (user extras).
func (p *Policy) Normalize(knownList func(string) bool, allowSchedules bool) error {
	p.Services = uniq(p.Services, KnownService)
	p.Categories = uniq(p.Categories, func(id string) bool { _, ok := lists.FindCategory(id); return ok })
	p.SafeSearch = p.SafeSearch.Normalize()
	var cls []CustomList
	ids := map[string]bool{}
	for _, c := range p.CustomLists {
		u, err := url.Parse(strings.TrimSpace(c.URL))
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("custom list URLs must be https://")
		}
		c.URL = u.String()
		c.Name = strings.TrimSpace(c.Name)
		if c.Name == "" {
			c.Name = u.Host
		}
		if len(c.Name) > 80 {
			c.Name = c.Name[:80]
		}
		c.Category = lists.NormalizeCategory(c.Category)
		if c.ID == "" || !strings.HasPrefix(c.ID, "u") || len(c.ID) > 40 {
			c.ID = ""
		}
		if c.ID == "" || ids[c.ID] {
			continue // the caller assigns ids
		}
		ids[c.ID] = true
		cls = append(cls, c)
	}
	if len(cls) > maxCustomLists {
		return errors.New("too many custom lists (max 20)")
	}
	p.CustomLists = cls
	p.Lists = uniq(p.Lists, func(id string) bool { return knownList(id) || ids[id] })
	if !allowSchedules {
		p.Schedules = nil
	}
	if len(p.Schedules) > 20 {
		return errors.New("too many schedules (max 20)")
	}
	for i := range p.Schedules {
		if err := p.Schedules[i].Validate(); err != nil {
			return err
		}
		p.Schedules[i].Services = uniq(p.Schedules[i].Services, KnownService)
		p.Schedules[i].Categories = uniq(p.Schedules[i].Categories, func(id string) bool { _, ok := lists.FindCategory(id); return ok })
		var allow []string
		for _, a := range p.Schedules[i].Allow {
			if d, ok := filter.CleanDomain(strings.TrimPrefix(strings.TrimSpace(a), "*.")); ok {
				allow = append(allow, d)
			}
		}
		p.Schedules[i].Allow = allow
	}
	if p.Lists == nil {
		p.Lists = []string{}
	}
	if p.Schedules == nil {
		p.Schedules = []Schedule{}
	}
	return nil
}

func uniq(in []string, ok func(string) bool) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] || !ok(v) {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func union(sets ...[]string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range sets {
		for _, v := range s {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

func minus(a, b []string) []string {
	drop := map[string]bool{}
	for _, v := range b {
		drop[v] = true
	}
	out := []string{}
	for _, v := range a {
		if !drop[v] {
			out = append(out, v)
		}
	}
	return out
}

// Input is everything needed to compile one device's (or the network's) effective policy.
type Input struct {
	Network      Policy
	NetworkLists []string // settings.EnabledLists
	User         *Policy  // owner's extras (nil when none)
	Device       *Policy  // device overrides (nil when none)
	AllLists     []lists.List

	NetAllow, NetBlock       map[string]bool // "default" rule scope
	UserAllow, UserBlock     map[string]bool
	DeviceAllow, DeviceBlock map[string]bool
}

// Compiled is an effective policy ready for the DNS hot path. "Base" parts come from the admin's
// network policy and can only be overridden by network allow rules; "Extra" parts were added by the
// device's owner or for the device and can be overridden by any allow rule.
type Compiled struct {
	BaseLists, ExtraLists       []string
	BaseServices, ExtraServices uint64
	BaseCategories              []string
	ExtraCategories             []string
	SafeSearch                  SafeSearch
	BaseSchedules               []compiledSchedule
	ExtraSchedules              []compiledSchedule
	CustomLists                 []CustomList // user-added lists in effect (for sync)

	NetAllow, NetBlock map[string]bool // network rules: block beats every allow
	Allow, Block       map[string]bool // user + device rules (allow excludes network blocks)

	masks atomic.Pointer[maskSet]
}

type maskSet struct {
	gen         uint64
	base, extra uint64
	baseSched   []uint64
	extraSched  []uint64
}

// Compile merges the network baseline with user extras and device overrides.
func Compile(in Input) *Compiled {
	c := &Compiled{NetAllow: in.NetAllow, NetBlock: in.NetBlock}
	if c.NetAllow == nil {
		c.NetAllow = map[string]bool{}
	}
	if c.NetBlock == nil {
		c.NetBlock = map[string]bool{}
	}
	net := in.Network
	c.BaseCategories = append([]string{}, net.Categories...)
	c.BaseLists = union(in.NetworkLists, lists.ForCategories(net.Categories, in.NetworkLists, in.AllLists))
	c.BaseServices = ServiceMask(net.Services)
	c.SafeSearch = net.SafeSearch.Normalize()

	var extraLists, extraSvc, extraCats []string
	for _, p := range []*Policy{in.User, in.Device} {
		if p == nil {
			continue
		}
		extraLists = append(extraLists, p.Lists...)
		for _, cl := range p.CustomLists {
			extraLists = append(extraLists, cl.ID)
			c.CustomLists = append(c.CustomLists, cl)
		}
		extraSvc = append(extraSvc, p.Services...)
		extraCats = append(extraCats, p.Categories...)
		c.SafeSearch = c.SafeSearch.Stricter(p.SafeSearch)
	}
	c.ExtraCategories = minus(union(extraCats), c.BaseCategories)
	raw := minus(union(extraLists), c.BaseLists)
	c.ExtraLists = minus(union(raw, lists.ForCategories(c.ExtraCategories, union(c.BaseLists, raw), in.AllLists)), c.BaseLists)
	c.ExtraServices = ServiceMask(extraSvc) &^ c.BaseServices

	active := union(c.BaseLists, c.ExtraLists)
	compileScheds := func(ss []Schedule) []compiledSchedule {
		var out []compiledSchedule
		for _, s := range ss {
			if !s.Enabled {
				continue
			}
			cs := compileSchedule(s)
			if s.Action == ActionBlockSelected {
				cs.lists = lists.ForCategories(s.Categories, active, in.AllLists)
			}
			out = append(out, cs)
		}
		return out
	}
	c.BaseSchedules = compileScheds(net.Schedules)
	if in.Device != nil {
		c.ExtraSchedules = compileScheds(in.Device.Schedules)
	}

	c.Allow, c.Block = map[string]bool{}, map[string]bool{}
	for _, m := range []map[string]bool{in.UserAllow, in.DeviceAllow} {
		for d := range m {
			if !c.NetBlock[d] {
				c.Allow[d] = true
			}
		}
	}
	for _, m := range []map[string]bool{in.UserBlock, in.DeviceBlock} {
		for d := range m {
			c.Block[d] = true
		}
	}
	return c
}

// ListsInUse returns every list id this policy may need (including schedule lists).
func (c *Compiled) ListsInUse() []string {
	out := union(c.BaseLists, c.ExtraLists)
	for _, s := range c.BaseSchedules {
		out = union(out, s.lists)
	}
	for _, s := range c.ExtraSchedules {
		out = union(out, s.lists)
	}
	return out
}

// Masks returns the list masks for idx, computed once per index generation.
func (c *Compiled) Masks(idx *filter.Index) (base, extra uint64) {
	m := c.masksFor(idx)
	return m.base, m.extra
}

func (c *Compiled) masksFor(idx *filter.Index) *maskSet {
	if m := c.masks.Load(); m != nil && m.gen == idx.Gen {
		return m
	}
	m := &maskSet{gen: idx.Gen, base: idx.Mask(c.BaseLists), extra: idx.Mask(c.ExtraLists) &^ idx.Mask(c.BaseLists)}
	for _, s := range c.BaseSchedules {
		m.baseSched = append(m.baseSched, idx.Mask(s.lists))
	}
	for _, s := range c.ExtraSchedules {
		m.extraSched = append(m.extraSched, idx.Mask(s.lists))
	}
	c.masks.Store(m)
	return m
}

// Now is the result of applying the schedules active at a moment.
type Now struct {
	BlockAll                    *Schedule // a block_all schedule is active (with its allowlist)
	blockAllow                  map[string]bool
	BaseServices, ExtraServices uint64
	BaseLists, ExtraLists       uint64
	Schedule                    string // name of the schedule that added blocking (for log reasons)
	permSvc, permLists          uint64 // blocking that applies all the time
}

// At evaluates the policy at time t against index idx. Allocation-free unless a schedule is active.
func (c *Compiled) At(t time.Time, idx *filter.Index) Now {
	m := c.masksFor(idx)
	n := Now{BaseServices: c.BaseServices, ExtraServices: c.ExtraServices, BaseLists: m.base, ExtraLists: m.extra,
		permSvc: c.BaseServices | c.ExtraServices, permLists: m.base | m.extra}
	apply := func(ss []compiledSchedule, masks []uint64, base bool) {
		for i := range ss {
			s := &ss[i]
			if !s.active(t) {
				continue
			}
			if s.src.Action == ActionBlockAll {
				if n.BlockAll == nil {
					n.BlockAll, n.blockAllow = &s.src, s.allow
				}
				continue
			}
			if n.Schedule == "" {
				n.Schedule = s.src.Name
			}
			if base {
				n.BaseServices |= s.services
				n.BaseLists |= masks[i]
			} else {
				n.ExtraServices |= s.services
				n.ExtraLists |= masks[i]
			}
		}
	}
	apply(c.BaseSchedules, m.baseSched, true)
	apply(c.ExtraSchedules, m.extraSched, false)
	return n
}

// BlockAllAllows reports whether domain is on the active block_all schedule's allowlist.
func (n Now) BlockAllAllows(domain string) bool {
	if len(n.blockAllow) == 0 {
		return false
	}
	_, ok := filter.Walk(domain, func(s string) bool { return n.blockAllow[s] })
	return ok
}

// FromSchedule reports whether a service / list block came only from an active schedule.
func (n Now) FromSchedule(svc, lists uint64) bool {
	return (svc != 0 && svc&n.permSvc == 0) || (lists != 0 && lists&n.permLists == 0)
}

// Effective is the merged policy as the apps see it (GET /api/v1/sync).
type Effective struct {
	Lists       []string     `json:"lists"`
	CustomLists []CustomList `json:"customLists"`
	Services    []string     `json:"services"`
	Categories  []string     `json:"categories"`
	SafeSearch  SafeSearch   `json:"safeSearch"`
	Schedules   []Schedule   `json:"schedules"`
}

// Effective summarises the compiled policy for sync.
func (c *Compiled) Effective() Effective {
	e := Effective{
		Lists:       union(c.BaseLists, c.ExtraLists),
		CustomLists: append([]CustomList{}, c.CustomLists...),
		Services:    ServiceIDs(c.BaseServices | c.ExtraServices),
		Categories:  union(c.BaseCategories, c.ExtraCategories),
		SafeSearch:  c.SafeSearch,
		Schedules:   []Schedule{},
	}
	for _, s := range c.BaseSchedules {
		e.Schedules = append(e.Schedules, s.src)
	}
	for _, s := range c.ExtraSchedules {
		e.Schedules = append(e.Schedules, s.src)
	}
	return e
}

// EffectiveRules returns the merged allow/block domain sets:
// block = network ∪ user ∪ device, allow = (network ∪ user ∪ device) − network block.
func (c *Compiled) EffectiveRules() (allow, block []string) {
	a, b := map[string]bool{}, map[string]bool{}
	for d := range c.NetBlock {
		b[d] = true
	}
	for d := range c.Block {
		b[d] = true
	}
	for d := range c.NetAllow {
		if !c.NetBlock[d] {
			a[d] = true
		}
	}
	for d := range c.Allow {
		a[d] = true
	}
	return sortedKeys(a), sortedKeys(b)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
