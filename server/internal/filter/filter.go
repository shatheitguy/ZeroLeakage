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
	"strings"
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
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// Match explains a decision.
type Match struct {
	Blocked  bool   `json:"blocked"`
	ListID   string `json:"listId"`
	ListName string `json:"listName"`
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Matched  string `json:"matched"`
}

const (
	UserAllowID = "user_allow"
	UserBlockID = "user_block"
)

// Index is an immutable rule index over many lists. Duplicates are stored once (first list wins).
type Index struct {
	sources     []Source
	blockExact  map[string]uint16
	blockSuffix map[string]uint16
	allowExact  map[string]uint16
	allowSuffix map[string]uint16
	Counts      map[string]int
}

// Builder accumulates lists into an Index.
type Builder struct{ idx *Index }

func NewBuilder() *Builder {
	return &Builder{&Index{
		blockExact: map[string]uint16{}, blockSuffix: map[string]uint16{},
		allowExact: map[string]uint16{}, allowSuffix: map[string]uint16{},
		Counts: map[string]int{},
	}}
}

// AddList parses r line by line; returns the number of usable rules.
func (b *Builder) AddList(src Source, r io.Reader, plainIsSuffix bool) int {
	if len(b.idx.sources) >= 65535 {
		return 0
	}
	id := uint16(len(b.idx.sources))
	b.idx.sources = append(b.idx.sources, src)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		rule, ok := ParseLine(sc.Text(), plainIsSuffix)
		if !ok {
			continue
		}
		n++
		var m map[string]uint16
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
		if _, exists := m[rule.Domain]; !exists {
			m[rule.Domain] = id
		}
	}
	b.idx.Counts[src.ID] = n
	return n
}

func (b *Builder) Build() *Index { return b.idx }

// Empty is an index with no rules.
var Empty = NewBuilder().Build()

// TotalRules is the number of distinct stored rules.
func (x *Index) TotalRules() int {
	return len(x.blockExact) + len(x.blockSuffix) + len(x.allowExact) + len(x.allowSuffix)
}

// Match decides a domain against the lists plus the caller's own allow/block sets
// (each user entry covers the domain and its subdomains). Returns nil when nothing matched.
func (x *Index) Match(domain string, userAllow, userBlock map[string]bool) *Match {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if s, ok := walk(d, func(s string) bool { return userAllow[s] }); ok {
		return &Match{false, UserAllowID, "Your allowlist", "Allowlisted", "@@||" + s + "^", s}
	}
	if s, ok := walk(d, func(s string) bool { return userBlock[s] }); ok {
		return &Match{true, UserBlockID, "Your blocklist", "User Blocklist", "||" + s + "^", s}
	}
	if id, ok := x.allowExact[d]; ok {
		return x.hit(false, id, "@@|"+d+"^", d)
	}
	if s, ok := walk(d, func(s string) bool { _, ok := x.allowSuffix[s]; return ok }); ok {
		return x.hit(false, x.allowSuffix[s], "@@||"+s+"^", s)
	}
	if id, ok := x.blockExact[d]; ok {
		return x.hit(true, id, "0.0.0.0 "+d, d)
	}
	if s, ok := walk(d, func(s string) bool { _, ok := x.blockSuffix[s]; return ok }); ok {
		return x.hit(true, x.blockSuffix[s], "||"+s+"^", s)
	}
	return nil
}

func (x *Index) hit(blocked bool, id uint16, rule, matched string) *Match {
	s := x.sources[id]
	return &Match{blocked, s.ID, s.Name, s.Category, rule, matched}
}

// walk calls f for the domain and each parent (never a bare TLD) and returns the first that matched.
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
