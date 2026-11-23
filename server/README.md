# ZeroLeakage Server

A privacy-first network protector for your home or office, in the spirit of AdGuard Home + Zenarmor
with a local CrowdSec-like "Guard", built to pair with the ZeroLeakage apps. See
[DESIGN.md](DESIGN.md) for the architecture, policy precedence and the app sync contract.

**No phoning home.** The server only talks to the internet to download filter lists and threat
feeds and to resolve through the encrypted upstream you pick. All detection runs locally; nothing is
reported anywhere, no cloud account, no telemetry.

## Features

| Area | What you get |
|---|---|
| **Network-wide filtering** | Every device on your Wi-Fi (TVs, consoles, IoT) is filtered: point the router's DNS at the server. |
| **Away from home** | Encrypted **DoH** (`https://your-host/dns-query/<device>`) and **DoT / Android Private DNS** (`<device>.your-host`). |
| **Filter lists** | AdGuard DNS, OISD, HaGeZi (incl. native trackers for Xiaomi, Samsung, Windows, TikTok…), StevenBlack, EasyPrivacy, URLhaus, Phishing Army, or any list by URL. |
| **Blocked services** | One click for YouTube, TikTok, Facebook, Instagram, WhatsApp, Messenger, Snapchat, X, Reddit, Discord, Telegram, Netflix, Twitch, Spotify, Pinterest, Tinder, Roblox, Fortnite/Epic, Steam, Prime Video, Disney+, Tumblr, Vimeo, Dailymotion, 9GAG, Imgur, Threads, Kick. The log says "Blocked service: TikTok". |
| **Web categories** | Ads & trackers, Telemetry, Malware & phishing, Crypto-mining *(on by default)*; Adult, Gambling, Social, Fake news, Piracy, VPN/DNS bypass *(opt-in)*. |
| **SafeSearch** | Google (every country domain), Bing, DuckDuckGo, YouTube Restricted Mode (moderate/strict), enforced with each provider's documented CNAME. |
| **Schedules** | Bedtime / homework windows per device or network: block everything except an allowlist, or block chosen services and categories. |
| **Local records** | `nas.lan → 192.168.1.10`, `*.home.lan`, CNAMEs, reverse lookups: answered locally, never sent upstream. |
| **Stop filtering bypass** | Blocks public DoH/DoT resolvers (Google, Cloudflare, Quad9, NextDNS, AdGuard, OpenDNS…) and iCloud Private Relay for LAN devices; keeps Firefox's canary domain NXDOMAIN. Never affects the server's own upstream. |
| **CNAME-cloaking protection** | Trackers hidden behind first-party names are blocked too. |
| **Clients & devices** | Auto-discovered clients with host names (reverse DNS on your router) and MAC vendor (host networking); name them in one click. Per-device policies. |
| **Guard** | Threat-IP feeds (Spamhaus DROP/DROPv6, FireHOL L1, Feodo, ET compromised, blocklist.de, CINS), malicious-answer blocking, detection of query floods, NXDOMAIN storms (DGA), DNS tunnelling, infected devices and sign-in brute force; alerts, bans with expiry, LAN **quarantine**, never-ban list, and a firewall blocklist export for OPNsense / MikroTik / the Windows app. |
| **Reports** | Per device: top services, categories, blocked domains, why things were blocked, hourly/daily timeline, Guard alerts. |
| **Users** | The admin runs the server; users link their apps (pairing code or password) and can only *add* protection for their own devices. |
| **App sync** | Linked apps get the full effective policy (lists, services, categories, SafeSearch, schedules, rules, Guard) and become an exact clone of the server's protection. |

## Run it

**Docker / Compose** (bridge networking, simplest):

```bash
cd server
docker compose up -d --build
# open http://<host>:3080 and create the admin account
```

**Host networking** (Linux; recommended so the server sees each device's real IP and MAC):

```bash
docker compose -f docker-compose.host.yml up -d --build
```

**Prebuilt image** (linux/amd64 + linux/arm64): `ghcr.io/shatheitguy/zeroleakage-server` (`latest` and
`X.Y.Z` from `server-v*` tags, `edge` from `main`).

**Unraid:** use `unraid/zeroleakage-server.xml` (give the container its own IP on `br0` so port 53 is free
and client IPs are real).

**From source** (Go 1.27+):

```bash
cd server
go run ./cmd/zeroleakage-server -data ./data -dns :5353 -http :3080
```

The image has a built-in health check (`zeroleakage-server -healthcheck`).

## Point your devices at it

| Where | How |
|---|---|
| Home Wi-Fi (everything) | Router → DHCP / DNS server → the server's IP |
| A single PC or TV | Set its DNS server to the server's IP |
| ZeroLeakage app | Dashboard → Devices → **Get a code**, then in the app *Profile → Account & sync → Connect to server* |
| Android on mobile data | Settings → Private DNS → `<device-id>.<your-hostname>` (needs DoT on 853 + a certificate) |

For DoT/HTTPS put a certificate for `your-host` **and** `*.your-host` at `data/tls.crt` + `data/tls.key`
(e.g. from your reverse proxy or certbot). It is reloaded automatically when it changes. Or keep the
server on plain HTTP `:3080` behind a TLS reverse proxy (Nginx Proxy Manager, Caddy, Cloudflare Tunnel)
and set `ZL_TRUST_PROXY=true`.

## Configuration

| Flag | Env | Default |
|---|---|---|
| `-data` | `ZL_DATA` | `./data` |
| `-dns` | `ZL_DNS_ADDR` | `:53` |
| `-http` | `ZL_HTTP_ADDR` | `:3080` |
| `-https` | `ZL_HTTPS_ADDR` | `:443` (only with a cert) |
| `-dot` | `ZL_DOT_ADDR` | `:853` (only with a cert) |
| `-cert` / `-key` | `ZL_TLS_CERT` / `ZL_TLS_KEY` | `<data>/tls.crt`, `<data>/tls.key` |
| `-trust-proxy` | `ZL_TRUST_PROXY` | `false` |
| `-debug` | `ZL_DEBUG` | `false` |
| – | `TZ` | time zone for schedules and reports |

Everything else (upstream, lists, policies, Guard, users) is set in the dashboard.

## Firewall blocklist (Guard bouncers)

Create a key under **Guard → Bouncers**, then fetch
`http(s)://<host>/api/v1/guard/blocklist.txt` with `X-Api-Key: <key>` (or `?key=<key>` for firewalls
that only accept a URL, such as an OPNsense *URL Table (IPs)* alias; note that a key in a URL can end
up in proxy logs). Linked apps can use their device token instead. Options: `?bans=0`, `?feeds=0`,
`?family=4|6`.

## Security notes

- Passwords are bcrypt-hashed; sessions, app tokens, bouncer keys and pairing codes are stored only as
  SHA-256 hashes. Pairing codes are one-time and expire after 10 minutes.
- Sign-ins, pairing and blocklist key failures are rate-limited per IP and feed Guard's brute-force
  detector; dashboard writes need a same-origin header (CSRF protection).
- Disabling a user immediately stops their sessions and device tokens.
- Lists added by users are only fetched over https from public addresses (no requests into your LAN).
- Device ids in DoH URLs / DoT hostnames identify a policy; they don't grant access to change anything.
- Rules live on the server in plain text because the server has to apply them. Keep `/data` on an
  encrypted disk if that matters to you.

## Honest limits

ZeroLeakage Server works at the **DNS level only**: it sees names, not traffic, and it never decrypts
or proxies TLS. Apps that use hard-coded IPs, their own built-in encrypted DNS or an unknown VPN can get
around it; services that also connect by IP (Telegram, WhatsApp) become unreliable rather than
impossible. For IP-level enforcement, feed the Guard blocklist to your firewall. Detection scenarios are
heuristics with conservative defaults. Details in [DESIGN.md](DESIGN.md#honest-limits).

## API

REST under `/api/v1`; see the table in [DESIGN.md](DESIGN.md#rest-api-v1) and the app contract in
[DESIGN.md](DESIGN.md#app-linking).
