# ZeroLeakage

Privacy shield with two independent apps. They share a visual identity, not code.

| Folder | Platform | Stack | Output |
|---|---|---|---|
| `windows/` | Windows 10/11 | .NET 10 · WPF · WiX 5 | `.msi` |
| `android/` | Android 10+ (API 29) | Kotlin · Jetpack Compose · VpnService | `.apk` |

## Windows

Dark-glass WPF shell: custom title bar, 3-mode switcher, bento dashboard, live packet/DNS feed,
firewall rules, DNS & telemetry, DeepScan AV, snapshots, the "Ask to Connect" toast and the post-install audit wizard.

The UI currently runs against `SimulatedProtectionEngine`, which changes nothing on the machine.
To wire in the real back-end, implement `IProtectionEngine` (`windows/ZeroLeakage.UI/Services/IProtectionEngine.cs`)
and swap it in `App.xaml.cs`.

```powershell
powershell -ExecutionPolicy Bypass -File windows\build-msi.ps1          # -> windows\artifacts\msi\*.msi
dotnet run --project windows\ZeroLeakage.UI                               # run the UI
windows\ZeroLeakage.UI\bin\Debug\...\ZeroLeakage.exe --selftest          # walk every page; exit 0 = clean
```

## Android

On-device DNS firewall: a local VPN that routes only DNS, attributes each lookup to the app that made it,
blocks telemetry/trackers and per-app (Wi-Fi / mobile) kill-switches, and resolves the rest over DNS-over-HTTPS.
Modes: Balanced, Strict Guard (unapproved apps get an Allow / Allow once / Block notification), Total Zero-Leak (pinned apps only).

```powershell
cd android
.\gradlew.bat assembleRelease        # -> app\build\outputs\apk\release\ZeroLeakage-1.0.0-release.apk
.\gradlew.bat testDebugUnitTest
```

The release APK is signed with the local debug key. Use a real signing key before publishing to a store.
