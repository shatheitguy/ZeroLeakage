// Package netinfo answers small questions about addresses: is this a LAN client, is it one of this
// server's own addresses, which gateway does this host use. Nothing here talks to the network.
package netinfo

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	thisNet   = netip.MustParsePrefix("0.0.0.0/8")
	reserved4 = netip.MustParsePrefix("240.0.0.0/4")
	bench     = netip.MustParsePrefix("198.18.0.0/15")
	ula       = netip.MustParsePrefix("fc00::/7")
)

// Parse parses an IP, unmapping IPv4-in-IPv6.
func Parse(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// IsLAN reports whether ip is a private / local-network address (RFC 1918, ULA, link-local, CGNAT, loopback).
func IsLAN(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip) || ula.Contains(ip)
}

// IsLANString is IsLAN for a textual address (false when it does not parse).
func IsLANString(s string) bool {
	a, ok := Parse(s)
	return ok && IsLAN(a)
}

// IsSpecial reports addresses that are never "malicious internet hosts": private, loopback, link-local,
// multicast, unspecified, CGNAT, 0/8, 240/4 (reserved + broadcast) and the benchmark range.
func IsSpecial(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return true
	}
	return IsLAN(ip) || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || thisNet.Contains(ip) || reserved4.Contains(ip) || bench.Contains(ip)
}

// SelfAddrs returns this machine's interface addresses (including loopback).
func SelfAddrs() []netip.Addr {
	out := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// LocalPrefixes returns the private networks this machine is attached to.
func LocalPrefixes() []netip.Prefix {
	var out []netip.Prefix
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && p.Addr().IsPrivate() {
			out = append(out, p.Masked())
		}
	}
	return out
}

// Gateways returns the default gateway(s) from /proc/net/route (Linux) plus the conventional ".1"
// address of each private IPv4 network this machine sits on. With Docker bridge networking every
// LAN query arrives from the bridge gateway, so it must never be banned.
func Gateways() []netip.Addr {
	var out []netip.Addr
	if f, err := os.Open("/proc/net/route"); err == nil {
		out = append(out, ParseRoutes(f)...)
		f.Close()
	}
	for _, p := range LocalPrefixes() {
		if p.Bits() <= 30 {
			out = append(out, p.Addr().Next())
		}
	}
	return out
}

// ParseRoutes extracts default gateways from the /proc/net/route format.
func ParseRoutes(r io.Reader) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[1] != "00000000" || f[2] == "00000000" {
			continue
		}
		b, err := hex.DecodeString(f[2])
		if err != nil || len(b) != 4 {
			continue
		}
		// little-endian
		out = append(out, netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}))
	}
	return out
}

// ParsePrefix accepts "1.2.3.4", "1.2.3.0/24", "2001:db8::/32" and returns a prefix.
func ParsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), true
	}
	a, ok := Parse(s)
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}
