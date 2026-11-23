// Package filter parses AdGuard / hosts-style DNS filter rules and matches domains against them.
//
// Semantics match the ZeroLeakage Android app:
//   - hosts files ("0.0.0.0 ads.example.com") and plain domain lists block that exact domain,
//     unless the list is curated (plainIsSuffix) in which case subdomains are blocked too;
//   - "||example.com^" blocks the domain and all subdomains;
//   - "@@||example.com^" is an exception (allow);
//   - anything that cannot be decided at DNS level (paths, regex, cosmetic rules, unknown $modifiers) is skipped.
//
// Precedence when matching: user allow > user block > list allow > list block.
package filter

import (
	"bufio"
	"io"
	"math/bits"
	"strings"
	"sync/atomic"
)

// Kind is what a parsed rule does.
type Kind int

const (
	BlockExact Kind = iota
	BlockSuffix
	AllowExact
	AllowSuffix
)

// Rule is one usable domain rule.
type Rule struct {
	Kind   Kind
	Domain string
}

var hostIPs = map[string]bool{"0.0.0.0": true, "127.0.0.1": true, "::": true, "::0": true, "::1": true, "0": true, "0:0:0:0:0:0:0:0": true}
var skipHosts = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true, "ip6-localhost": true,
	"ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true, "ip6-allrouters": true,
	"ip6-allhosts": true, "0.0.0.0": true,
}
var okModifiers = map[string]bool{"important": true, "third-party": true, "3p": true, "all": true, "document": true, "doc": true}

// ParseLine parses one filter-list line. ok is false for comments and rules that are not DNS-level.
func ParseLine(raw string, plainIsSuffix bool) (Rule, bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return Rule{}, false
	}
	switch line[0] {
	case '!', '#', '[':
		return Rule{}, false
	}
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#?#") || strings.Contains(line, "#$#") {
		return Rule{}, false
	}
	allow := false
	if strings.HasPrefix(line, "@@") {
		allow = true
		line = line[2:]
	}
	if strings.HasPrefix(line, "||") {
		body := line[2:]
		var domainPart, rest string
		if caret := strings.IndexByte(body, '^'); caret >= 0 {
			domainPart, rest = body[:caret], body[caret+1:]
		} else if dollar := strings.IndexByte(body, '$'); dollar >= 0 {
			domainPart, rest = body[:dollar], body[dollar:]
		} else {
			domainPart = strings.TrimRight(body, "|")
		}
		rest = strings.TrimPrefix(rest, "|")
		if rest != "" {
			if !strings.HasPrefix(rest, "$") {
				return Rule{}, false // a path after ^
			}
			for _, m := range strings.Split(rest[1:], ",") {
				if !okModifiers[strings.ToLower(strings.TrimSpace(m))] {
					return Rule{}, false
				}
			}
		}
		d, ok := CleanDomain(domainPart)
		if !ok {
			return Rule{}, false
		}
		if allow {
			return Rule{AllowSuffix, d}, true
		}
		return Rule{BlockSuffix, d}, true
	}
	if allow {
		d, ok := CleanDomain(strings.TrimRight(line, "^|"))
		if !ok {
			return Rule{}, false
		}
		return Rule{AllowSuffix, d}, true
	}
	if line[0] == '|' || line[0] == '/' || strings.ContainsAny(line, "$*") {
		return Rule{}, false
	}
	if hash := strings.IndexByte(line, '#'); hash >= 0 {
		line = strings.TrimSpace(line[:hash])
	}
	if line == "" {
		return Rule{}, false
	}
	tokens := strings.Fields(line)
	var host string
	switch {
	case len(tokens) >= 2 && hostIPs[tokens[0]]:
		host = tokens[1]
	case len(tokens) == 1:
		host = tokens[0]
	default:
		return Rule{}, false
	}
	if skipHosts[strings.ToLower(host)] {
		return Rule{}, false
	}
	d, ok := CleanDomain(host)
	if !ok {
		return Rule{}, false
	}
	if plainIsSuffix {
		return Rule{BlockSuffix, d}, true
	}
	return Rule{BlockExact, d}, true
}

// CleanDomain lower-cases and validates a domain; bare IPs and single labels are rejected.
func CleanDomain(raw string) (string, bool) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasPrefix(d, "-") || strings.Contains(d, "..") {
		return "", false
	}
	allDigits := true
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return "", false
		}
		if !(c >= '0' && c <= '9' || c == '.') {
			allDigits = false
		}
	}
	if allDigits {
		return "", false
	}
	return d, true
}

// Source labels where a rule came from.
type Source struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Category   string `json:"category"`   // display name, e.g. "Ads & trackers"
	CategoryID string `json:"categoryId"` // e.g. "ads"
}

// Match explains a decision.
type Match struct {
	Blocked    bool   `json:"blocked"`
	ListID     string `json:"listId"`
	ListName   string `json:"listName"`
	Category   string `json:"category"`
	CategoryID string `json:"categoryId,omitempty"`
	Rule       string `json:"rule"`
	Matched    string `json:"matched"`
}

const (
	UserAllowID = "user_allow"
	UserBlockID = "user_block"
	// MaxSources is how many lists one index can hold (each list is one bit of a uint64 mask).
	MaxSources = 64
)

// AllLists is a mask that selects every list in an index.
const AllLists = ^uint64(0)

var genCounter atomic.Uint64

// Index is an immutable rule index over up to 64 lists. Every domain maps to the bitmask of the lists
// that contain it, so one shared index can serve many policies that each use a different set of lists.
type Index struct {
	Gen         uint64 // unique per built index (policies cache their list masks per generation)
	sources     []Source
	byID        map[string]int
	blockExact  map[string]uint64
	blockSuffix map[string]uint64
	allowExact  map[string]uint64
	allowSuffix map[string]uint64
	Counts      map[string]int
}

// Builder accumulates lists into an Index.
type Builder struct{ idx *Index }

func NewBuilder() *Builder {
	return &Builder{&Index{
		byID:       map[string]int{},
		blockExact: map[string]uint64{}, blockSuffix: map[string]uint64{},
		allowExact: map[string]uint64{}, allowSuffix: map[string]uint64{},
		Counts: map[string]int{},
	}}
}

// AddList parses r line by line; returns the number of usable rules (-1 when the index is full).
func (b *Builder) AddList(src Source, r io.Reader, plainIsSuffix bool) int {
	if len(b.idx.sources) >= MaxSources {
		return -1
	}
	id := len(b.idx.sources)
	bit := uint64(1) << id
	b.idx.sources = append(b.idx.sources, src)
	b.idx.byID[src.ID] = id
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		rule, ok := ParseLine(sc.Text(), plainIsSuffix)
		if !ok {
			continue
		}
		n++
		var m map[string]uint64
		switch rule.Kind {
		case BlockExact:
			m = b.idx.blockExact
		case BlockSuffix:
			m = b.idx.blockSuffix
		case AllowExact:
			m = b.idx.allowExact
		default:
			m = b.idx.allowSuffix
		}
		m[rule.Domain] |= bit
	}
	b.idx.Counts[src.ID] = n
	return n
}

func (b *Builder) Build() *Index {
	b.idx.Gen = genCounter.Add(1)
	return b.idx
}

// Empty is an index with no rules.
var Empty = NewBuilder().Build()

// TotalRules is the number of distinct stored rules.
func (x *Index) TotalRules() int {
	return len(x.blockExact) + len(x.blockSuffix) + len(x.allowExact) + len(x.allowSuffix)
}

// Sources lists the indexed lists in bit order.
func (x *Index) Sources() []Source { return x.sources }

// Mask returns the bitmask selecting the given list ids (unknown ids are ignored).
func (x *Index) Mask(ids []string) uint64 {
	var m uint64
	for _, id := range ids {
		if i, ok := x.byID[id]; ok {
			m |= 1 << i
		}
	}
	return m
}

// Bit returns the mask bit of one list (0 when not indexed).
func (x *Index) Bit(id string) uint64 {
	if i, ok := x.byID[id]; ok {
		return 1 << i
	}
	return 0
}

// CategoryOf returns the category of the first list in mask (for tagging queries in reports).
func (x *Index) CategoryOf(mask uint64) (id, name string) {
	if mask == 0 {
		return "", ""
	}
	s := x.sources[bits.TrailingZeros64(mask)]
	return s.CategoryID, s.Category
}

// MatchUser decides a domain against allow/block domain sets (each entry covers the domain and its
// subdomains). Allow beats block. Returns nil when neither matched.
func MatchUser(domain string, userAllow, userBlock map[string]bool) *Match {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if len(userAllow) > 0 {
		if s, ok := walk(d, func(s string) bool { return userAllow[s] }); ok {
			return &Match{Blocked: false, ListID: UserAllowID, ListName: "Your allowlist", Category: "Allowlisted", Rule: "@@||" + s + "^", Matched: s}
		}
	}
	if len(userBlock) > 0 {
		if s, ok := walk(d, func(s string) bool { return userBlock[s] }); ok {
			return &Match{Blocked: true, ListID: UserBlockID, ListName: "Your blocklist", Category: "User Blocklist", Rule: "||" + s + "^", Matched: s}
		}
	}
	return nil
}

// MatchLists decides a domain against the lists selected by mask: list exceptions beat list blocks.
// seen is the mask of every indexed list that lists the domain as blocked (selected or not), which
// callers use to tag allowed queries with a category.
func (x *Index) MatchLists(domain string, mask uint64) (m *Match, seen uint64) {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if mask != 0 {
		if v := x.allowExact[d] & mask; v != 0 {
			return x.hit(false, v, "@@|"+d+"^", d), 0
		}
		if s, ok := walk(d, func(s string) bool { return x.allowSuffix[s]&mask != 0 }); ok {
			return x.hit(false, x.allowSuffix[s]&mask, "@@||"+s+"^", s), 0
		}
	}
	if v := x.blockExact[d]; v != 0 {
		if v&mask != 0 {
			return x.hit(true, v&mask, "0.0.0.0 "+d, d), v
		}
		seen |= v
	}
	for s := d; ; {
		if v := x.blockSuffix[s]; v != 0 {
			if v&mask != 0 {
				return x.hit(true, v&mask, "||"+s+"^", s), seen | v
			}
			seen |= v
		}
		dot := strings.IndexByte(s, '.')
		if dot < 0 || dot == len(s)-1 {
			break
		}
		s = s[dot+1:]
		if !strings.Contains(s, ".") {
			break
		}
	}
	return nil, seen
}

// Match is MatchUser followed by MatchLists (user allow > user block > list allow > list block).
func (x *Index) Match(domain string, userAllow, userBlock map[string]bool, mask uint64) *Match {
	if m := MatchUser(domain, userAllow, userBlock); m != nil {
		return m
	}
	m, _ := x.MatchLists(domain, mask)
	return m
}

func (x *Index) hit(blocked bool, mask uint64, rule, matched string) *Match {
	s := x.sources[bits.TrailingZeros64(mask)]
	return &Match{Blocked: blocked, ListID: s.ID, ListName: s.Name, Category: s.Category, CategoryID: s.CategoryID, Rule: rule, Matched: matched}
}

// Walk calls f for the domain and each parent (never a bare TLD) and returns the first that matched.
func Walk(d string, f func(string) bool) (string, bool) { return walk(d, f) }

func walk(d string, f func(string) bool) (string, bool) {
	for {
		if f(d) {
			return d, true
		}
		dot := strings.IndexByte(d, '.')
		if dot < 0 || dot == len(d)-1 {
			return "", false
		}
		d = d[dot+1:]
		if !strings.Contains(d, ".") {
			return "", false
		}
	}
}
