package guard

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"sort"
)

// u128 is an IPv6 address (IPv4 is stored v4-mapped) as a number, so v4 and v6 share one sorted table.
type u128 struct{ hi, lo uint64 }

func toU(a netip.Addr) u128 {
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

func (u u128) addr(v4 bool) netip.Addr {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], u.hi)
	binary.BigEndian.PutUint64(b[8:], u.lo)
	a := netip.AddrFrom16(b)
	if v4 {
		return a.Unmap()
	}
	return a
}

func (u u128) less(v u128) bool { return u.hi < v.hi || (u.hi == v.hi && u.lo < v.lo) }

var maxU = u128{^uint64(0), ^uint64(0)}

func (u u128) inc() u128 {
	lo := u.lo + 1
	hi := u.hi
	if lo == 0 {
		hi++
	}
	return u128{hi, lo}
}

func (u u128) dec() u128 {
	hi := u.hi
	if u.lo == 0 {
		hi--
	}
	return u128{hi, u.lo - 1}
}

// ones returns a value with the low n bits set (0 <= n <= 128).
func ones(n int) u128 {
	switch {
	case n <= 0:
		return u128{}
	case n >= 128:
		return maxU
	case n >= 64:
		return u128{(1 << (n - 64)) - 1, ^uint64(0)}
	}
	return u128{0, (1 << n) - 1}
}

func (u u128) or(v u128) u128 { return u128{u.hi | v.hi, u.lo | v.lo} }

func (u u128) trailingZeros() int {
	if u.lo != 0 {
		return bits.TrailingZeros64(u.lo)
	}
	if u.hi != 0 {
		return 64 + bits.TrailingZeros64(u.hi)
	}
	return 128
}

// span returns the first and last address of a prefix.
func span(p netip.Prefix) (lo, hi u128) {
	p = p.Masked()
	lo = toU(p.Addr())
	host := p.Addr().BitLen() - p.Bits()
	return lo, lo.or(ones(host))
}

// Range is a run of addresses with the set of feeds (bitmask) that list them.
type Range struct {
	lo, hi u128
	feeds  uint32
}

// Set is an immutable, sorted list of disjoint ranges: lookups are a binary search.
type Set struct{ r []Range }

// EmptySet has no ranges.
var EmptySet = &Set{}

// Len is the number of disjoint ranges.
func (s *Set) Len() int { return len(s.r) }

// Lookup returns the feeds that list a (0 when none).
func (s *Set) Lookup(a netip.Addr) uint32 {
	if s == nil || len(s.r) == 0 || !a.IsValid() {
		return 0
	}
	x := toU(a)
	i := sort.Search(len(s.r), func(i int) bool { return !s.r[i].hi.less(x) })
	if i < len(s.r) && !x.less(s.r[i].lo) {
		return s.r[i].feeds
	}
	return 0
}

// Builder collects prefixes per feed and produces a Set.
type Builder struct{ items []Range }

// Add records that feed (0..31) lists prefix p.
func (b *Builder) Add(p netip.Prefix, feed int) {
	lo, hi := span(p)
	b.items = append(b.items, Range{lo, hi, 1 << feed})
}

type event struct {
	pos   u128
	feed  int
	start bool
}

// Build sweeps over range boundaries so overlapping entries from different feeds keep exact attribution.
func (b *Builder) Build() *Set {
	evs := make([]event, 0, len(b.items)*2)
	for _, it := range b.items {
		f := bits.TrailingZeros32(it.feeds)
		evs = append(evs, event{it.lo, f, true})
		if it.hi != maxU {
			evs = append(evs, event{it.hi.inc(), f, false})
		}
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].pos.less(evs[j].pos) })
	var counts [32]int
	var mask uint32
	var out []Range
	var segStart u128
	for i := 0; i < len(evs); {
		pos := evs[i].pos
		if mask != 0 && segStart.less(pos) {
			out = appendRange(out, Range{segStart, pos.dec(), mask})
		}
		for ; i < len(evs) && evs[i].pos == pos; i++ {
			if evs[i].start {
				counts[evs[i].feed]++
			} else {
				counts[evs[i].feed]--
			}
		}
		mask = 0
		for f, c := range counts {
			if c > 0 {
				mask |= 1 << f
			}
		}
		segStart = pos
	}
	if mask != 0 { // ran to the end of the address space
		out = appendRange(out, Range{segStart, maxU, mask})
	}
	return &Set{out}
}

func appendRange(out []Range, r Range) []Range {
	if n := len(out); n > 0 && out[n-1].feeds == r.feeds && out[n-1].hi.inc() == r.lo {
		out[n-1].hi = r.hi
		return out
	}
	return append(out, r)
}

var v4Lo, v4Hi = span(netip.MustParsePrefix("::ffff:0.0.0.0/96"))

// Prefixes returns the minimal CIDR list covering every range listed by a feed in mask.
func (s *Set) Prefixes(mask uint32) []netip.Prefix {
	var out []netip.Prefix
	var cur *Range
	flush := func() {
		if cur != nil {
			out = appendCIDRs(out, cur.lo, cur.hi)
			cur = nil
		}
	}
	for i := range s.r {
		r := s.r[i]
		if r.feeds&mask == 0 {
			flush()
			continue
		}
		if cur != nil && cur.hi.inc() == r.lo {
			cur.hi = r.hi
			continue
		}
		flush()
		cur = &Range{lo: r.lo, hi: r.hi}
	}
	flush()
	return out
}

// appendCIDRs splits [lo, hi] into aligned blocks.
func appendCIDRs(out []netip.Prefix, lo, hi u128) []netip.Prefix {
	for !hi.less(lo) {
		v4 := !lo.less(v4Lo) && !v4Hi.less(lo)
		maxHost := 128
		if v4 {
			maxHost = 32
		}
		k := lo.trailingZeros()
		if k > maxHost {
			k = maxHost
		}
		for k > 0 && hi.less(lo.or(ones(k))) {
			k--
		}
		last := lo.or(ones(k))
		bitsLen := 128
		if v4 {
			bitsLen = 32
		}
		out = append(out, netip.PrefixFrom(lo.addr(v4), bitsLen-k))
		if last == maxU {
			break
		}
		lo = last.inc()
	}
	return out
}
