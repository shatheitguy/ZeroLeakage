package policy

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/shatheitguy/ZeroLeakage/server/internal/filter"
)

// Rewrite is a local DNS record answered by the server itself (e.g. nas.lan -> 192.168.1.10).
// Domain may start with "*." to match every subdomain (not the bare name).
type Rewrite struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	Type   string `json:"type"` // A | AAAA | CNAME
	Value  string `json:"value"`
}

// Validate normalises and checks a rewrite.
func (r *Rewrite) Validate() error {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), "."))
	base := strings.TrimPrefix(d, "*.")
	if base == "" || strings.ContainsAny(base, " */:") || len(base) > 253 || strings.HasPrefix(base, ".") || strings.Contains(base, "..") {
		return errors.New("enter a host name like nas.lan or *.home.lan")
	}
	r.Domain = d
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Value = strings.TrimSpace(r.Value)
	switch r.Type {
	case "A":
		a, err := netip.ParseAddr(r.Value)
		if err != nil || !a.Unmap().Is4() {
			return errors.New("an A record needs an IPv4 address")
		}
		r.Value = a.Unmap().String()
	case "AAAA":
		a, err := netip.ParseAddr(r.Value)
		if err != nil || !a.Is6() || a.Is4In6() {
			return errors.New("an AAAA record needs an IPv6 address")
		}
		r.Value = a.String()
	case "CNAME":
		v, ok := filter.CleanDomain(r.Value)
		if !ok {
			return errors.New("a CNAME needs a host name")
		}
		if v == base {
			return errors.New("a CNAME can't point at itself")
		}
		r.Value = v
	default:
		return errors.New("type must be A, AAAA or CNAME")
	}
	return nil
}

// Rewrites is an immutable lookup table for local records.
type Rewrites struct {
	exact map[string][]Rewrite
	wild  map[string][]Rewrite // keyed by the part after "*."
	ptr   map[string]string    // reverse name (in-addr.arpa / ip6.arpa) -> host
}

// NewRewrites compiles a table (invalid entries are skipped).
func NewRewrites(rs []Rewrite) *Rewrites {
	t := &Rewrites{exact: map[string][]Rewrite{}, wild: map[string][]Rewrite{}, ptr: map[string]string{}}
	for _, r := range rs {
		if err := r.Validate(); err != nil {
			continue
		}
		if base, ok := strings.CutPrefix(r.Domain, "*."); ok {
			t.wild[base] = append(t.wild[base], r)
			continue
		}
		t.exact[r.Domain] = append(t.exact[r.Domain], r)
		if r.Type == "A" || r.Type == "AAAA" {
			if rev, err := dns.ReverseAddr(r.Value); err == nil {
				rev = strings.TrimSuffix(rev, ".")
				if _, dup := t.ptr[rev]; !dup {
					t.ptr[rev] = r.Domain
				}
			}
		}
	}
	return t
}

// Empty reports whether the table has no records.
func (t *Rewrites) Empty() bool { return t == nil || (len(t.exact) == 0 && len(t.wild) == 0) }

// Lookup returns the records for name: exact match first, then the most specific wildcard.
func (t *Rewrites) Lookup(name string) []Rewrite {
	if t.Empty() {
		return nil
	}
	if rs, ok := t.exact[name]; ok {
		return rs
	}
	if len(t.wild) == 0 {
		return nil
	}
	d := name
	for {
		dot := strings.IndexByte(d, '.')
		if dot < 0 || dot == len(d)-1 {
			return nil
		}
		d = d[dot+1:]
		if rs, ok := t.wild[d]; ok {
			return rs
		}
	}
}

// PTR returns the host for a reverse-lookup name of a rewritten address.
func (t *Rewrites) PTR(name string) (string, bool) {
	if t == nil {
		return "", false
	}
	h, ok := t.ptr[name]
	return h, ok
}
