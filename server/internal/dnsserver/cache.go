package dnsserver

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// cache is a small TTL-respecting answer cache keyed by name/type/class/DO bit.
type cache struct {
	mu    sync.Mutex
	max   int
	items map[string]cacheItem
}

type cacheItem struct {
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

func newCache(max int) *cache { return &cache{max: max, items: map[string]cacheItem{}} }

func key(req *dns.Msg) string {
	q := req.Question[0]
	do := "0"
	if o := req.IsEdns0(); o != nil && o.Do() {
		do = "1"
	}
	var b strings.Builder
	b.WriteString(strings.ToLower(q.Name))
	b.WriteByte('/')
	b.WriteString(dns.TypeToString[q.Qtype])
	b.WriteByte('/')
	b.WriteString(dns.ClassToString[q.Qclass])
	b.WriteByte('/')
	b.WriteString(do)
	return b.String()
}

func (c *cache) get(req *dns.Msg) *dns.Msg {
	k := key(req)
	c.mu.Lock()
	it, ok := c.items[k]
	if ok && time.Now().After(it.expires) {
		delete(c.items, k)
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		return nil
	}
	m := it.msg.Copy()
	m.Id = req.Id
	// Age the TTLs so clients see the time remaining.
	age := uint32(time.Since(it.stored).Seconds())
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > age {
				rr.Header().Ttl -= age
			} else {
				rr.Header().Ttl = 1
			}
		}
	}
	return m
}

func (c *cache) put(req, resp *dns.Msg) {
	if resp.Truncated || (resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError) {
		return
	}
	ttl := uint32(300)
	found := false
	for _, sec := range [][]dns.RR{resp.Answer, resp.Ns} {
		for _, rr := range sec {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if !found || rr.Header().Ttl < ttl {
				ttl, found = rr.Header().Ttl, true
			}
		}
	}
	if ttl < 5 {
		ttl = 5
	}
	if ttl > 3600 {
		ttl = 3600
	}
	now := time.Now()
	c.mu.Lock()
	if len(c.items) >= c.max { // drop ~10% (map iteration order is random)
		n := c.max / 10
		for k := range c.items {
			delete(c.items, k)
			if n--; n <= 0 {
				break
			}
		}
	}
	c.items[key(req)] = cacheItem{resp.Copy(), now, now.Add(time.Duration(ttl) * time.Second)}
	c.mu.Unlock()
}

func (c *cache) clear() {
	c.mu.Lock()
	c.items = map[string]cacheItem{}
	c.mu.Unlock()
}
