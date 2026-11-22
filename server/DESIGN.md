# ZeroLeakage Server: design

A self-hosted DNS filtering server in the spirit of AdGuard Home / Pi-hole, built for the ZeroLeakage
apps. It protects **every device on your network** (Wi-Fi: point the router's DNS at it) and **your
phones and laptops anywhere** (mobile data: encrypted DoH / DoT to the server). Accounts are
**optional**: the server works with no sign-in at all; signing in only adds rule sync across devices.

## Goals

| # | Goal |
|---|------|
| 1 | Network-wide blocking of ads, trackers, telemetry and malware for every device, no app needed. |
| 2 | The same protection away from home over DoH (`https://host/dns-query/<device>`) and DoT (`<device>.dns.host:853`). |
| 3 | Per-device identity and policy (kids' tablet stricter than the work laptop). |
| 4 | Optional accounts: link the ZeroLeakage Windows/Android apps and sync allow/block rules and filter-list choices. |
| 5 | Never forced: apps keep working fully offline/local; the server is an opt-in upgrade. |
| 6 | One container, one data volume, runs on Unraid/Docker/a Raspberry Pi. |

Non-goals (for now): DHCP server, recursive resolution from the root (we forward to encrypted upstreams), HTTP proxying.

## Architecture

```
                ┌─────────────────────────── zeroleakage-server ───────────────────────────┐
 LAN devices ──▶│ :53 UDP/TCP  ─┐                                                          │
 (router DNS)   │               │   identify client ─▶ policy ─▶ filter ─┬─ blocked ─▶ NXDOMAIN / 0.0.0.0
 phones on 4G ─▶│ :443 DoH  ────┼─▶ (IP / DoH token / DoT SNI)            └─ allowed ─▶ cache ─▶ upstream DoH
 laptops away ─▶│ :853 DoT  ────┘                                                    (failover, DNSSEC AD)
                │                                                                          │
 apps / admin ─▶│ :3080 HTTP  web dashboard + REST API (/api/v1)  ── SQLite (data/zl.db)   │
                └──────────────────────────────────────────────────────────────────────────┘
```

Single Go binary (`zeroleakage-server`), packages:

| Package | Responsibility |
|---|---|
| `internal/filter` | AdGuard-style rule parser and in-memory index. Same semantics as the Android app: hosts / plain domains = exact, `||d^` = domain + subdomains, `@@` exceptions, user allow > user block > list allow > list block. |
| `internal/lists` | Filter-list catalog (AdGuard DNS, OISD, HaGeZi, StevenBlack, …), downloads, refresh every 24 h, on-disk cache. |
| `internal/upstream` | DoH client with failover across resolvers, temporary mark-down, optional plain-DNS fallback. |
| `internal/dnsserver` | UDP/TCP listener, DoH handler, DoT listener; client identification; cache; query log. |
| `internal/store` | SQLite: settings, users, devices, rules, query log (ring, retention days). |
| `internal/api` | REST API + session/token auth + embedded web dashboard. |

## Client identification

1. **DoH path token**: `https://dns.example.com/dns-query/<deviceId>` (what the apps use on mobile data).
2. **DoT SNI**: `<deviceId>.dns.example.com` (Android Private DNS hostname; needs a wildcard cert).
3. **Source IP**: LAN clients mapped by IP/CIDR in the dashboard ("Living-room TV = 192.168.1.40").
4. Otherwise the **default** policy.

Device IDs are random 10-char base32 strings; they identify, they don't authenticate (like NextDNS).
Anyone with an ID can only *use* that policy, not change it.

## Policy model

```
Policy (default + one per device, inherits default unless overridden)
  lists:        enabled filter-list ids
  userAllow:    domains (domain + subdomains)
  userBlock:    domains
  blockMode:    nxdomain | null_ip (0.0.0.0 / ::)
  safeSearch:   off | on            (phase 2)
  schedule:     none | bedtime rules (phase 2)
```

## Accounts and sync (optional)

- Off by default: the admin account (created on first run) can do everything.
- When enabled, users register on the dashboard (or the admin invites them). Each user owns devices.
- **Linking an app**: in the app, *Account & sync → Connect to server* → server URL + sign in, or scan a
  QR code from the dashboard. The server issues a **device token** (random 256-bit, stored hashed) and a
  device id. The app then:
  - uses `https://server/dns-query/<deviceId>` as its DoH resolver (Android) / resolver (Windows), and
  - syncs rules through `GET/PUT /api/v1/sync` with `Authorization: Bearer <token>`.
- Sync document = `{ version, lists[], allow[], block[], appRules? }`. Each item carries `updatedAt`;
  merge is per-item last-writer-wins with tombstones, so offline edits on two phones both survive.
- Rules live on the server in plaintext because the server must apply them; the data volume should be on
  an encrypted disk. Passwords: bcrypt. Tokens: SHA-256 hashes only.

## REST API (v1)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/status` | none | version, uptime, totals (for the apps' "server reachable" check) |
| POST | `/api/v1/auth/login` | – | user/password → session cookie |
| POST | `/api/v1/auth/setup` | first run | create the admin account |
| GET | `/api/v1/stats` | session | queries, blocked %, top domains/clients |
| GET | `/api/v1/querylog` | session | recent queries (filter by device / blocked) |
| GET/PUT | `/api/v1/lists` | session | catalog + enabled lists; POST `/refresh` |
| GET/POST/DELETE | `/api/v1/rules` | session | allow/block domains (default policy) |
| GET/POST/DELETE | `/api/v1/devices` | session | devices, LAN IP mapping, per-device policy, link QR |
| POST | `/api/v1/devices/link` | session | issue a device token for an app |
| GET/PUT | `/api/v1/sync` | device token | app rule sync (merge) |
| GET | `/api/v1/check?domain=` | session | why a domain is blocked/allowed (rule + list) |

## Ports and TLS

| Port | Use | TLS |
|---|---|---|
| 53 UDP/TCP | LAN DNS | – |
| 853 | DoT | cert required (`tls.crt/tls.key` in data dir, or ACME later) |
| 443 | DoH | cert, **or** run DoH on `:8053` plain HTTP behind a reverse proxy (Nginx Proxy Manager / Cloudflare Tunnel) |
| 3080 | dashboard + API | behind the same proxy for remote access |

## Phases

1. **Core (this commit)**: filter engine, lists, upstream DoH failover, cache, UDP/TCP/DoH/DoT listeners,
   SQLite store, admin setup/login, stats, query log, lists/rules/devices API, sync API, dashboard,
   Dockerfile, Unraid template, tests.
2. Apps: *Account & sync → Connect to server* in Android and Windows (resolver switch + rule sync).
3. Safe search, schedules, per-device blocked services (TikTok, YouTube…), ACME certificates,
   Prometheus metrics, multi-server sync.
