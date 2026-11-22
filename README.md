<div align="center">

<img src="docs/assets/logo.svg" width="112" alt="ZeroLeakage logo" />

# ZeroLeakage

**Zero bits leaked.** A privacy shield for Windows and Android that cuts telemetry, trackers and
unknown apps off the network, and encrypts every DNS lookup that is allowed through.

[![Release](https://img.shields.io/github/v/release/shatheitguy/ZeroLeakage?color=00F5A0&labelColor=12151E&style=flat-square)](https://github.com/shatheitguy/ZeroLeakage/releases/latest)
![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-7B61FF?labelColor=12151E&style=flat-square)
![Android](https://img.shields.io/badge/Android-10%2B-7B61FF?labelColor=12151E&style=flat-square)

[**Website**](https://shatheitguy.github.io/ZeroLeakage/) ·
[**Download**](https://github.com/shatheitguy/ZeroLeakage/releases/latest) ·
[Build from source](#build-from-source)

</div>

---

## Download

| Platform | File | Notes |
|---|---|---|
| Windows 10 / 11 (x64) | [`ZeroLeakage-1.0.0-x64.msi`](https://github.com/shatheitguy/ZeroLeakage/releases/download/v1.0.0/ZeroLeakage-1.0.0-x64.msi) | Self-contained: .NET is bundled, nothing else to install. |
| Android 10+ | [`ZeroLeakage-1.0.0-release.apk`](https://github.com/shatheitguy/ZeroLeakage/releases/download/v1.0.0/ZeroLeakage-1.0.0-release.apk) | Sideload: allow "Install unknown apps" for your browser or file manager. |

## Three protection modes

| | Mode | What it does |
|---|---|---|
| `01` | **Balanced Shield** | Telemetry, ad trackers and analytics SDKs are silently dropped. Apps keep working as before. |
| `02` | **Strict Guard** | Everything in Balanced, plus default-deny: any app you haven't approved must ask before it gets online (Allow / Allow once / Block). |
| `03` | **Total Zero-Leak** | Hard lockdown. Only apps you pin may reach the internet. |

## Windows

A dark-glass WPF desktop app with a frameless window, an animated mode switcher and a live connection feed.

- **Dashboard:** bento metrics (telemetry purged, DNS trackers dropped, firewall lockdown, DeepScan) and a live, filterable feed with one-click *Block domain* / *Kill app network*.
- **Firewall rules:** per-app Wi-Fi / Ethernet / VPN access and global kill switches.
- **DNS & telemetry:** blocklists, encrypted DNS-over-HTTPS resolvers, OS telemetry services and trace-log wiping.
- **DeepScan AV:** quick / full scans and a quarantine vault.
- **Snapshots & settings:** restore points, start with Windows, tray behaviour.
- **Ask to Connect:** a toast slides in when an unknown app tries to get online in Strict Guard.
- **Post-install audit:** scores your privacy and applies hardening in one pass (a snapshot is taken first).
- **Update window:** temporarily opens the network for 15 minutes so updates can run, then locks down again.

> **Status:** the Windows UI is complete and runs on `SimulatedProtectionEngine`, which **does not change the system yet**.
> The real back-end plugs in behind [`IProtectionEngine`](windows/ZeroLeakage.UI/Services/IProtectionEngine.cs).

## Android

A real on-device DNS firewall built on Android's `VpnService`. Nothing is routed off the phone except encrypted DNS.

- **Local DNS-only VPN:** only the virtual DNS address is routed into the tunnel, so normal app traffic never passes through it and battery use stays low.
- **Per-app attribution:** every lookup is matched to the app that made it (`getConnectionOwnerUid`).
- **Blocklists:** OS/OEM telemetry, ad and tracker networks, analytics SDKs, and malware/phishing hosts, plus your own custom domains.
- **Per-app firewall:** Wi-Fi and mobile-data kill switches for each app.
- **Encrypted DNS:** allowed lookups are resolved over DNS-over-HTTPS (Cloudflare, Quad9 or Mullvad).
- **Strict Guard prompts:** an actionable notification (Allow / Allow once / Block) appears the first time an unapproved app reaches out.

> Tip: set Android **Private DNS** to *Off* or *Automatic*. A custom Private DNS host bypasses the on-device filter.

## How the Android shield works

```
 app ──DNS query──▶ 10.111.222.2 (virtual, inside the local VPN)
                        │
                        ├─ who asked?  getConnectionOwnerUid → package
                        ├─ blocklists + per-app rules + current mode
                        │
            blocked ◀───┴───▶ allowed
           NXDOMAIN            DNS-over-HTTPS (TLS) → resolver
```

## Build from source

The two apps are fully independent: separate folders, toolchains and outputs, and no shared code.

```text
windows/   .NET 10 · WPF · WiX 5        →  .msi
android/   Kotlin · Jetpack Compose     →  .apk
docs/      project website (GitHub Pages)
```

**Windows** (needs the .NET 10 SDK):

```powershell
powershell -ExecutionPolicy Bypass -File windows\build-msi.ps1     # -> windows\artifacts\msi\ZeroLeakage-1.0.0-x64.msi
dotnet run --project windows\ZeroLeakage.UI                          # run the UI
```

**Android** (needs JDK 17+ and the Android SDK):

```powershell
cd android
.\gradlew.bat assembleRelease      # -> app\build\outputs\apk\release\ZeroLeakage-1.0.0-release.apk
.\gradlew.bat testDebugUnitTest
```

The release APK is signed with the local debug key. Use your own signing key before publishing to a store.

**Brand assets:** the app icon, installer artwork and site logo are generated from one geometry:

```powershell
powershell -ExecutionPolicy Bypass -File windows\tools\New-AppIcon.ps1 -OutFile windows\ZeroLeakage.UI\Assets\ZeroLeakage.ico
powershell -ExecutionPolicy Bypass -File windows\tools\New-InstallerArt.ps1 -OutDir windows\ZeroLeakage.Installer\Art
```

## Privacy

ZeroLeakage has no account, no analytics and no servers of its own. Rules, counters and the live feed stay on your device.
The only traffic it creates is the encrypted DNS-over-HTTPS request to the resolver you choose.
