# ZeroLeakage Server: design

A self-hosted network protector in the spirit of AdGuard Home + Zenarmor, plus a local CrowdSec-like
"Guard", built for the ZeroLeakage apps. It protects **every device on your network** (point the
router's DNS at it) and **your phones and laptops anywhere** (encrypted DoH / DoT to the server).

**Mission:** no one and no app should be able to track you or collect your data and metadata. So:
privacy-first defaults, and the server never phones home. Its only outbound traffic is filter-list and
threat-feed downloads and the encrypted upstream resolver you choose. All "intelligence" (threat
matching, attack detection, device identification) runs locally; nothing is reported to anyone, no
cloud console, no account-based service.

## Goals

| # | Goal |
|---|------|
| 1 | Network-wide blocking of ads, trackers, telemetry and malware for every device, no app needed. |
| 2 | The same protection away from home over DoH (`https://host/dns-query/<device>`) and DoT (`<device>.dns.host:853`). |
| 3 | Zenarmor-style control: one-click blocked services, web categories, SafeSearch, schedules, per-device policy, reports. |
| 4 | Guard: threat-IP feeds, attack detection, bans/quarantine, and a blocklist for firewalls. |
| 5 | Multiple users, administered only by the admin. Users can add protection for their own devices, never remove the network's. |
| 6 | Apps become an exact clone of the server's protection (pairing + full policy sync), and keep working offline. |
| 7 | One container, one data volume, runs on Unraid/Docker/a Raspberry Pi (amd64 + arm64). |

Non-goals: DHCP server, recursive resolution from the root (we forward to encrypted upstreams), HTTP
proxying or TLS inspection (see [Limits](#honest-limits)).

## Architecture

```
                ┌──────────────────────────── zeroleakage-server ─────────────────────────────┐
 LAN devices ──▶│ :53 UDP/TCP ─┐                                                              │
 phones on 4G ─▶│ :443 DoH ────┼─▶ identify client ─▶ Guard ban? ─▶ policy decision ──┬─ block ─▶ NXDOMAIN / 0.0.0.0
 laptops away ─▶│ :853 DoT ────┘  (DoH path, DoT SNI,  (quarantine /   (schedules, local   ├─ local record / SafeSearch CNAME
                │                  IP / CIDR)            refuse)         records, rules,    └─ allow ─▶ cache ─▶ upstream DoH
                │                                                        services, lists)        │  (failover, DNSSEC AD)
                │                       answer checks: CNAME cloaking, threat-IP feeds ◀─────────┘
 apps / admin ─▶│ :3080 HTTP  dashboard + REST API (/api/v1) ── SQLite (data/zeroleakage.db)       │
 firewalls ────▶│             GET /api/v1/guard/blocklist.txt (bouncer key / device token)          │
                └──────────────────────────────────────────────────────────────────────────────────┘
```

| Package | Responsibility |
|---|---|
| `internal/filter` | AdGuard-style rule parser and index. Each domain maps to a **bitmask of the lists** that contain it (max 64 lists), so one shared index serves many policies that each use different lists. |
| `internal/lists` | Filter-list catalog, **web categories** (curated lists per category), downloads (daily), on-disk cache. User-added lists are fetched over https from public addresses only (SSRF guard). |
| `internal/policy` | Blocked-services catalog, SafeSearch table, schedules, filtering-bypass hosts, local records, and the merge of network + user + device policies into a compiled, allocation-light structure. |
| `internal/upstream` | DoH client with failover across resolvers, temporary mark-down, optional plain-DNS fallback. |
| `internal/dnsserver` | UDP/TCP/DoT/DoH listeners, client identification, the decision pipeline, answer cache, query log. |
| `internal/guard` | Threat-IP feeds (sorted disjoint ranges + binary search), behaviour detectors, decisions (bans), bouncer export. |
| `internal/clients` | Client discovery (counts per address), reverse DNS via the LAN router, MAC from `/proc/net/arp`, vendor from an embedded OUI table. |
| `internal/store` | SQLite: settings + JSON policies, users, sessions, devices, rules, pairing codes, clients, Guard decisions/alerts/bouncers, query log. |
| `internal/api` | REST API, sessions/CSRF/roles, pairing and sync, embedded single-file dashboard. |

The DNS hot path never touches the database: `Engine.Reload` compiles every device's effective policy
into an immutable snapshot (swapped atomically), list masks are cached per index generation, and
Guard bans/feeds are read through atomic pointers.

## Client identification

1. **DoH path token**: `https://dns.example.com/dns-query/<deviceId>` (what the apps use on mobile data).
2. **DoT SNI**: `<deviceId>.dns.example.com` (Android Private DNS hostname; needs a wildcard cert).
3. **Source IP / CIDR**: LAN devices mapped in the dashboard. The **Clients** page lists every address
   seen (first/last seen, query count, host name from the router via reverse DNS, MAC + vendor when
   running with host networking) with "Name this device" to create or extend a device.
4. Otherwise the **network default** policy.

Device IDs are random 10-char base32 strings; they identify, they don't authenticate (like NextDNS).

## Policy model

Three layers, merged per device:

```
Network policy (admin)       lists (= Filter lists page), services, categories, SafeSearch, schedules,
                             allow/block rules ("default" scope)          ← the baseline, always applies
User extras (per user)       extra lists, own custom lists, services, categories, SafeSearch,
                             allow/block rules ("user:<id>")               ← all of that user's devices
Device overrides (per device) extra lists, services, categories, SafeSearch, schedules,
                             allow/block rules ("device:<id>")
```

**Admin baseline always wins.** Users and devices can only *add*:

- `effectiveBlock = networkBlock ∪ userBlock ∪ deviceBlock`
- `effectiveAllow = (networkAllow ∪ userAllow ∪ deviceAllow) − networkBlock`
- Network lists, services, categories and SafeSearch can't be switched off by users; SafeSearch merges
  to the stricter setting. Only the admin can pause a device.

Decision order for one query (first match wins):

1. Device paused (admin only) → allow.  2. `use-application-dns.net` → NXDOMAIN (Firefox canary).
3. Active **block-all schedule** → block unless on the schedule's allowlist.
4. **Local records** (A/AAAA/CNAME, `*.wildcard`, PTR for their addresses) → answered locally.
5. **Network block rule** → block (beats every allow).
6. **SafeSearch** → CNAME to the engine's restricted host, resolved upstream (Google `forcesafesearch.google.com`,
   Bing `strict.bing.com`, DuckDuckGo `safe.duckduckgo.com`, YouTube `restrictmoderate.youtube.com` / `restrict.youtube.com`).
7. **Network allow rule** → allow.
8. **Filtering bypass** (default for LAN clients) → block public DoH/DoT resolvers and iCloud Private Relay.
9. **Network services** (incl. active network schedules) → "Blocked service: TikTok".
10. **Network lists** (enabled lists + lists of network categories) → block, list exceptions allow.
11. **User/device allow** → allow; **user/device block** → block.
12. **User/device services, lists and categories** (incl. device schedules) → block.
13. Otherwise resolve. Answers are then checked for **CNAME cloaking** and **threat IPs** (Guard).

Answers are cached exactly as received from the upstream; policy is applied on top for every client,
so one device's allowlist or SafeSearch setting never leaks to another device through the cache.

### Web categories

| Category | Default | Lists used when none of that category is enabled |
|---|---|---|
| Ads & trackers | on | built-in trackers + analytics (AdGuard DNS, EasyPrivacy… on the Lists page) |
| Telemetry | on | built-in OS/OEM telemetry |
| Malware & phishing | on | built-in malware + HaGeZi TIF mini |
| Crypto-mining | on | NoCoin |
| Adult content | off | HaGeZi NSFW |
| Gambling | off | HaGeZi Gambling (medium) |
| Social networks | off | StevenBlack social |
| Fake news | off | StevenBlack fakenews |
| Piracy & torrents | off | HaGeZi Anti-Piracy |
| VPN, proxy & DNS bypass | off | HaGeZi DoH/VPN/proxy bypass |

Lists are only downloaded when some policy needs them. Switching a category off for the network also
switches off the network's lists of that category.

### Schedules

Per network or per device: days (the day the window starts), `HH:MM` start/end in the server's time zone
(`TZ`), windows past midnight allowed. Actions: `block_all` (with an allowlist) or `block_selected`
(services and categories). Evaluated per query against the engine clock (injectable for tests).

## Users and roles

- The **admin** (created on first run) administers everything: settings, network policy, lists,
  local records, clients, Guard, users, all devices. More admins can be created.
- **Users** are created by the admin (Users page) or by public sign-up when the admin enables it
  (off by default). A user sees and manages only their own devices, their own rules and their own
  extras; they can't change server settings, the network policy, lists, Guard, users or other
  users' devices.
- Disabling a user ends their sessions and stops their device tokens and pairing codes. Deleting a
  user removes their devices, rules and policy. The last admin can't be disabled, demoted or deleted.

## App linking

All app endpoints are JSON under `/api/v1`. Device tokens are 256-bit random values stored only as
SHA-256 hashes; send them as `Authorization: Bearer <token>`.

### Pair (recommended: no password on the phone)

1. Dashboard → Devices → **Get a code**: `POST /devices/pair-code {name?, scope?}` (session + `X-ZL-Request: 1`)
   → `{code: "ZL-ABCD-EFGH", expiresAt}`. 8 characters from an unambiguous alphabet, one use,
   10 minutes, stored hashed, owned by the signed-in user. `scope` is `"user"` (default: the device
   shares the owner's rules and extras) or `"device"` (its own).
2. App: `POST /devices/pair {code, deviceName, platform: "android"|"windows"}` (no auth, rate-limited per IP
   like sign-in, the code is burned on use) →
   `{token, device: {id, name, dohUrl, dotHost, platform}, server: {name, version, hostname}, username}`.

Or with a password: `POST /devices/link {username, password, deviceName, platform}` → same response.

### Sync

`GET /sync?since=<ms>` (Bearer device token):

```jsonc
{
  "rules": [{"kind":"block","domain":"x.com","updatedAt":1732400000000,"deleted":false}], // editable rules (user scope), changed since `since`
  "lists": ["…"],                        // network-enabled list ids (unchanged legacy field)
  "serverTime": 1732400000000, "deviceId": "…", "dohUrl": "…", "dotHost": "…",
  "policy": {                            // the EFFECTIVE policy for this device
    "lists": ["trackers","hagezi_pro"],  // catalog ids incl. category lists
    "customLists": [{"id":"u2_ab12cd34","name":"Mine","url":"https://…","category":"custom"}],
    "services": ["tiktok","youtube"], "categories": ["ads","telemetry","malware","cryptomining"],
    "safeSearch": {"google":true,"bing":false,"duckduckgo":false,"youtube":"moderate"},
    "blockMode": "nxdomain", "schedules": [/* Schedule objects */],
    "guard": {"enabled":true,"dropMaliciousIPs":true}, "bypassBlocking": true
  },
  "effective": {"allow": ["…"], "block": ["…"]},    // merged rules (formula above)
  "locked": {"lists": [], "services": [], "categories": [], "blockDomains": [], "safeSearch": {}}, // admin baseline: show "Set by admin"
  "userPolicy": {"lists":[], "customLists":[], "services":[], "categories":[], "safeSearch":{}, "updatedAt": 0},
  "policyVersion": "9f2c…"               // hash of policy+effective+locked+userPolicy: skip work when unchanged
}
```

`PUT /sync` (Bearer device token):

```jsonc
{
  "rules": [
    {"domain":"x.com","action":"block","op":"add"},           // app format
    {"kind":"allow","domain":"y.com","updatedAt":…,"deleted":true}  // server format, both accepted
  ],
  "userPolicy": {"lists":[], "customLists":[{"name":"…","url":"https://…"}], "services":[], "categories":[], "safeSearch":{}, "updatedAt": 0}
}
```

Rules merge per item, last writer wins, with tombstones (adding to one list removes the domain from the
other). `userPolicy` is a patch (only the fields sent change), last writer wins on `updatedAt`, and is
applied to the token owner's user scope (or the device's own scope for `scope:"device"` pairings).
Custom lists must be https; the server gives them stable ids. Response:
`{applied, userPolicyApplied, serverTime, policyVersion}`.

### Guard blocklist

`GET /guard/blocklist.txt` with a bouncer key (`X-Api-Key`, `Authorization: Bearer`, or `?key=`) **or a
device token**: plain text, one IP/CIDR per line, `#` comments. `?bans=0` / `?feeds=0` to leave a part
out, `?family=4|6`. Linked Windows PCs pull Guard bans with the same token they sync with.

## Guard (local CrowdSec-like engine)

| Piece | What it does |
|---|---|
| **Threat feeds** (daily, no account) | Spamhaus DROP (EDROP is merged into it) and DROPv6, FireHOL Level 1, abuse.ch Feodo Tracker *(DNS + export by default)*; Emerging Threats compromised, blocklist.de all, CINS Army *(export only by default: attacker lists cause false positives on shared hosting)*. Private/reserved and absurdly wide entries are dropped. |
| **Answer filtering** | An allowed answer containing an address from a DNS feed is blocked ("Malicious IP 1.2.3.4 (Spamhaus DROP)") and counts as a malware hit. |
| **Detectors** (per client, tumbling windows, bounded memory) | Query flood (qps), NXDOMAIN storm (distinct non-existent names: DGA malware), DNS tunnelling (many distinct long / high-entropy subdomains of one domain, TXT/NULL heavy), infected device (repeated malware/phishing lookups), sign-in brute force (failed dashboard/app sign-ins and pairing attempts). Each: on/off, alert or ban, threshold, window, ban length. |
| **Decisions** | Bans with expiry stored in SQLite, manual ban/unban (IP or CIDR). LAN clients are **quarantined** by default (everything blocked except the quarantine allowlist and the dashboard's hostname); internet DoH/DoT clients get **REFUSED**. |
| **Never ban** | This server's own addresses, the default gateway(s) and each LAN's `.1` (with Docker bridge networking every LAN query arrives from the bridge gateway), loopback, plus your list. |
| **Bouncers** | API keys created in the dashboard for OPNsense URL tables, MikroTik scripts or the Windows app. |

## REST API (v1)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/status` | none | version, uptime, totals |
| POST | `/auth/setup` · `/auth/login` · `/auth/signup` · `/auth/logout` | – | first admin, sessions |
| GET | `/me` | session | current user |
| GET/PUT | `/settings` | admin | upstream, block mode, bypass mode, PTR resolver, hostname, retention, sign-up |
| GET | `/resolvers` | session | known DoH resolvers |
| GET / PUT | `/lists` | session / admin | catalog + network-enabled lists; `POST /lists/refresh`, `POST/DELETE /lists/custom` (admin) |
| GET | `/services` · `/categories` | session | blocked-services and category catalogs |
| GET / PUT | `/policy?scope=default\|user\|user:<id>\|device:<id>` | session (network: admin writes) | services, categories, SafeSearch, schedules, extra lists |
| GET/POST/DELETE | `/rules?scope=…` | session | allow/block domains |
| GET | `/check?domain=&device=&client=` | session | why a domain is blocked/allowed |
| GET/POST/PUT/DELETE | `/devices`, `/devices/{id}` | session | devices (own devices for users; pause and IP mapping admin only) |
| POST | `/devices/{id}/link` | session | issue a device token |
| POST | `/devices/pair-code` | session | one-time pairing code |
| POST | `/devices/pair` · `/devices/link` | – (rate-limited) | app linking (code / password) |
| GET/PUT | `/sync` | device token | full policy sync |
| GET / POST | `/clients` · `/clients/name` | admin | discovered clients, name / attach to a device |
| GET/POST/DELETE | `/rewrites`, `/rewrites/{id}` | admin | local DNS records |
| GET | `/stats?hours=` · `/querylog` · `/reports?hours=&device=&client=` | session (users: own devices) | overview, log, per-device reports (services, categories, blocked, timeline, Guard alerts) |
| GET/POST/PUT/DELETE | `/users`, `/users/{id}` | admin | user management |
| GET | `/guard` | admin | config, feeds, bans, alerts, bouncers, stats |
| PUT | `/guard/config` | admin | Guard settings |
| POST / DELETE | `/guard/bans`, `/guard/bans/{id}`, `POST /guard/unban` | admin | manual decisions |
| POST | `/guard/feeds/refresh` | admin | refresh feeds now |
| GET | `/guard/alerts` | admin | alert history |
| GET/POST/DELETE | `/guard/bouncers` | admin | bouncer keys |
| GET | `/guard/blocklist.txt` | bouncer key / device token / admin | firewall blocklist |

Dashboard writes need the `X-ZL-Request: 1` header (CSRF); sign-ins, pairing and blocklist key
failures are rate-limited per IP and feed Guard's brute-force detector.

## Ports and TLS

| Port | Use | TLS |
|---|---|---|
| 53 UDP/TCP | LAN DNS | – |
| 853 | DoT | cert required (`tls.crt/tls.key` in data dir) |
| 443 | DoH | cert, **or** DoH on `:3080` plain HTTP behind a reverse proxy |
| 3080 | dashboard + API | behind the same proxy for remote access |

## Honest limits

- **DNS level only.** The server sees names and answers, not traffic. It can't block an app that uses
  hard-coded IP addresses, its own DoH inside the app, or a VPN it can't recognise by name. Bypass
  blocking covers the well-known public resolvers and iCloud Private Relay, not every possible one.
- **No TLS inspection, ever.** It never decrypts or proxies HTTPS. "L7" here means names: services
  and categories are domain sets, so blocking is per hostname, not per URL or in-app feature.
- Services like Telegram and WhatsApp also connect by IP; DNS blocking makes them unreliable, not
  impossible. Use the Guard blocklist on a firewall for IP-level enforcement.
- Device identification by IP needs real client addresses: Docker bridge networking may hide them,
  so use host networking or a macvlan/br0 IP. MAC/vendor detection needs host networking (Linux).
- Detectors are heuristics with conservative defaults (alerts for the noisy ones); tune thresholds
  to your network.
