# ZeroLeakage Server

Network-wide DNS filtering for your home or office, in the spirit of AdGuard Home and Pi-hole, built to
pair with the ZeroLeakage apps. See [DESIGN.md](DESIGN.md) for the architecture.

- **Every device on your Wi-Fi** is filtered: point your router's DNS at the server. TVs, consoles and IoT
  gear included, with no app needed.
- **Phones and laptops on mobile data** stay protected over encrypted **DoH**
  (`https://your-host/dns-query/<device>`) or **DoT / Android Private DNS** (`<device>.your-host`).
- **AdGuard-style filter lists:** AdGuard DNS, OISD, HaGeZi (incl. native trackers for Xiaomi, Samsung,
  Windows, TikTok…), StevenBlack, EasyPrivacy, URLhaus, Phishing Army, parental lists, or any list by URL.
- **Per-device policy:** name devices by LAN IP / CIDR or link them by app, then add allow/block rules
  for one device, all of a user's devices, or the whole network. Pause protection per device.
- **CNAME-cloaking protection:** trackers hidden behind first-party names are blocked too.
- **Encrypted upstreams with failover:** Cloudflare, Quad9, Mullvad, AdGuard, Google… or your own
  DoH URL; optional plain-DNS fallback (your router) if every encrypted resolver is unreachable.
- **Dashboard:** queries and blocks per hour, top blocked domains and clients, a searchable query log
  with one-click allow/block, and a "why is this blocked?" checker.
- **Optional accounts:** the server runs with just the admin. Turn on sign-up to let people create
  accounts and link the ZeroLeakage apps, which then sync allow/block rules across all their devices.
  Nobody is ever forced to sign in.

## Run it

**Docker / Compose**

```bash
cd server
docker compose up -d --build
# open http://<host>:3080 and create the admin account
```

**Unraid:** use `unraid/zeroleakage-server.xml` (give the container its own IP on `br0` so port 53 is free).

**From source** (Go 1.27+):

```bash
cd server
go run ./cmd/zeroleakage-server -data ./data -dns :5353 -http :3080
```

## Point your devices at it

| Where | How |
|---|---|
| Home Wi-Fi (everything) | Router → DHCP / DNS server → the server's IP |
| A single PC or TV | Set its DNS server to the server's IP |
| Android on mobile data | Settings → Private DNS → `<device-id>.<your-hostname>` (needs DoT on 853 + a certificate) |
| ZeroLeakage app | Profile → Account & sync → Connect to server (uses `https://<host>/dns-query/<device-id>`) |

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

Everything else (upstream, lists, block mode, sign-up, retention, public hostname) is set in the dashboard.

## Security notes

- Passwords are bcrypt-hashed; sessions and app tokens are stored only as SHA-256 hashes.
- Logins are rate-limited per IP; dashboard writes need a same-origin header (CSRF protection).
- Device ids in DoH URLs / DoT hostnames identify a policy; they don't grant access to change anything.
- Rules live on the server in plain text because the server has to apply them. Keep `/data` on an
  encrypted disk if that matters to you.

## API

REST under `/api/v1`; see the table in [DESIGN.md](DESIGN.md#rest-api-v1). Linked apps authenticate
with `Authorization: Bearer <device token>` and sync through `GET/PUT /api/v1/sync`.
