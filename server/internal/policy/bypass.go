package policy

import "strings"

// Bypass modes (server setting BlockBypass).
const (
	BypassOff = "off"
	BypassLAN = "lan" // default: LAN clients only (phones away from home already use this server via DoH/DoT)
	BypassAll = "all"
)

// bypassDomains are public DoH/DoT resolvers that browsers, phones and apps use to go around the
// network's DNS, plus iCloud Private Relay. Each entry covers its subdomains. The server's own
// upstream connections never go through this filter (they are made directly, not via our DNS).
var bypassDomains = map[string]string{
	"dns.google": "Google DNS", "dns.google.com": "Google DNS", "8888.google": "Google DNS", "dns64.dns.google": "Google DNS",
	"cloudflare-dns.com": "Cloudflare DNS", "one.one.one.one": "Cloudflare DNS", "1dot1dot1dot1.cloudflare-dns.com": "Cloudflare DNS",
	"cloudflare-gateway.com": "Cloudflare Gateway",
	"dns.quad9.net":          "Quad9", "dns9.quad9.net": "Quad9", "dns10.quad9.net": "Quad9", "dns11.quad9.net": "Quad9", "dns12.quad9.net": "Quad9",
	"doh.opendns.com": "OpenDNS", "doh.familyshield.opendns.com": "OpenDNS", "doh.umbrella.com": "OpenDNS", "dns.umbrella.com": "OpenDNS",
	"dns.adguard-dns.com": "AdGuard DNS", "dns-unfiltered.adguard.com": "AdGuard DNS", "dns.adguard.com": "AdGuard DNS",
	"dns-family.adguard.com": "AdGuard DNS", "unfiltered.adguard-dns.com": "AdGuard DNS", "family.adguard-dns.com": "AdGuard DNS",
	"d.adguard-dns.com": "AdGuard DNS",
	"dns.nextdns.io":    "NextDNS", "doh.nextdns.io": "NextDNS", "chrome.dns.nextdns.io": "NextDNS",
	"dns.mullvad.net": "Mullvad DNS", "doh.mullvad.net": "Mullvad DNS", "adblock.doh.mullvad.net": "Mullvad DNS",
	"dns.controld.com": "Control D", "freedns.controld.com": "Control D",
	"doh.cleanbrowsing.org": "CleanBrowsing", "doh.dns.sb": "DNS.SB", "dot.sb": "DNS.SB",
	"dns0.eu": "dns0.eu", "zero.dns0.eu": "dns0.eu", "kids.dns0.eu": "dns0.eu", "open.dns0.eu": "dns0.eu",
	"dns.alidns.com": "AliDNS", "doh.pub": "DNSPod", "dot.pub": "DNSPod", "doh.360.cn": "360 DNS",
	"dns.switch.ch": "SWITCH", "dns.digitale-gesellschaft.ch": "Digitale Gesellschaft", "doh.ffmuc.net": "FFMUC",
	"doh.libredns.gr": "LibreDNS", "doh.applied-privacy.net": "Applied Privacy", "dns.twnic.tw": "TWNIC",
	"ordns.he.net": "Hurricane Electric", "doh.xfinity.com": "Xfinity", "doh.tiar.app": "Tiar", "odvr.nic.cz": "CZ.NIC",
	"dns.njal.la": "Njalla", "wikimedia-dns.org": "Wikimedia DNS", "doh.sandbox.opendns.com": "OpenDNS",
	"dns.brahma.world": "Brahma", "dns.decloudus.com": "DeCloudUs", "doh.quickline.ch": "Quickline",
	"dns.comss.one": "Comss", "doh.dns4all.eu": "dns4all", "dns.rabbitdns.org": "RabbitDNS",
	// iCloud Private Relay: a negative answer for these makes Apple devices fall back to the network's DNS.
	"mask.icloud.com": "iCloud Private Relay", "mask-h2.icloud.com": "iCloud Private Relay",
}

// BypassProvider returns the provider name when domain (or a parent) is a known filtering-bypass host.
func BypassProvider(domain string) (string, bool) {
	d := domain
	for {
		if p, ok := bypassDomains[d]; ok {
			return p, true
		}
		dot := strings.IndexByte(d, '.')
		if dot < 0 || dot == len(d)-1 {
			return "", false
		}
		d = d[dot+1:]
		if strings.IndexByte(d, '.') < 0 {
			return "", false
		}
	}
}

// BypassDomains returns the built-in list (for the dashboard).
func BypassDomains() map[string]string {
	out := make(map[string]string, len(bypassDomains))
	for k, v := range bypassDomains {
		out[k] = v
	}
	return out
}
