using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.Services.Dns;

namespace ZeroLeakage.UI.Services;

/// <summary>
/// Self-contained stand-in for the ZeroLeakage Core service. Generates a realistic live feed,
/// statistics, "Ask to Connect" prompts (Strict Guard), scans and audits so the UI is fully
/// interactive without the privileged back-end. It changes nothing on the machine.
/// </summary>
public sealed class SimulatedProtectionEngine : IProtectionEngine
{
    private enum Kind { Telemetry, Tracker, Normal, Doh, Update }

    private sealed record Template(string Process, string? Service, string Destination, int Port, Kind Kind, string Category);

    private static readonly Template[] Templates =
    {
        new("svchost.exe", "DiagTrack", "v10.events.data.microsoft.com", 443, Kind.Telemetry, "OS Telemetry"),
        new("svchost.exe", "DiagTrack", "settings-win.data.microsoft.com", 443, Kind.Telemetry, "OS Telemetry"),
        new("CompatTelRunner.exe", null, "watson.telemetry.microsoft.com", 443, Kind.Telemetry, "OS Telemetry"),
        new("svchost.exe", "dmwappushservice", "self.events.data.microsoft.com", 443, Kind.Telemetry, "OS Telemetry"),
        new("SearchHost.exe", null, "browser.events.data.msn.com", 443, Kind.Telemetry, "Bing Telemetry"),
        new("WidgetService.exe", null, "assets.msn.com", 443, Kind.Tracker, "Widgets Feed"),
        new("msedge.exe", null, "nav.smartscreen.microsoft.com", 443, Kind.Telemetry, "SmartScreen Ping"),
        new("OneDrive.exe", null, "vortex.data.microsoft.com", 443, Kind.Telemetry, "OS Telemetry"),
        new("Spotify.exe", null, "app-measurement.com", 443, Kind.Tracker, "Ad Tracker"),
        new("Discord.exe", null, "sentry.io", 443, Kind.Tracker, "Crash Analytics"),
        new("Code.exe", null, "dc.services.visualstudio.com", 443, Kind.Telemetry, "App Telemetry"),
        new("brave.exe", null, "www.google-analytics.com", 443, Kind.Tracker, "Ad Tracker"),
        new("brave.exe", null, "stats.g.doubleclick.net", 443, Kind.Tracker, "Ad Tracker"),
        new("steam.exe", null, "api.mixpanel.com", 443, Kind.Tracker, "Analytics"),
        new("brave.exe", null, "1.1.1.1", 443, Kind.Doh, "Encrypted DoH"),
        new("ZeroLeakage.Core.exe", null, "9.9.9.9", 443, Kind.Doh, "Encrypted DoH"),
        new("brave.exe", null, "github.com", 443, Kind.Normal, "HTTPS"),
        new("Discord.exe", null, "gateway.discord.gg", 443, Kind.Normal, "WebSocket"),
        new("Spotify.exe", null, "spclient.wg.spotify.com", 443, Kind.Normal, "HTTPS"),
        new("steam.exe", null, "steamcdn-a.akamaihd.net", 443, Kind.Normal, "CDN"),
        new("Code.exe", null, "marketplace.visualstudio.com", 443, Kind.Normal, "HTTPS"),
        new("svchost.exe", "wuauserv", "dl.delivery.mp.microsoft.com", 443, Kind.Update, "Windows Update"),
        new("MoUsoCoreWorker.exe", null, "fe3cr.delivery.mp.microsoft.com", 443, Kind.Update, "Windows Update"),
    };

    private static readonly (string Name, string Path, string? Publisher, bool Signed, string Dest, string Ip)[] UnknownApps =
    {
        ("AdobeARM.exe", @"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe", "Adobe Inc.", true, "armmf.adobe.com", "23.45.112.18"),
        ("nvcontainer.exe", @"C:\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe", "NVIDIA Corporation", true, "telemetry.gfe.nvidia.com", "8.249.13.254"),
        ("update_helper.exe", @"C:\Users\Public\AppData\Local\Temp\update_helper.exe", null, false, "cdn-dl-mirror.top", "185.220.101.47"),
        ("GameOverlay.exe", @"C:\Games\Launcher\GameOverlay.exe", null, false, "metrics.overlay-stats.io", "104.21.66.10"),
        ("TeamViewer_Service.exe", @"C:\Program Files\TeamViewer\TeamViewer_Service.exe", "TeamViewer Germany GmbH", true, "router15.teamviewer.com", "37.252.230.144"),
    };

    private readonly Random _rng = new();
    private readonly object _gate = new();
    private readonly HashSet<string> _blockedDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _killedApps = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _approvedApps = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<NetworkScope, bool> _globalScopes = new() { [NetworkScope.WiFi] = true, [NetworkScope.Lan] = true, [NetworkScope.Wan] = true };
    private readonly List<AppRule> _apps;
    private readonly FilterListService _filters;
    private readonly List<DohResolver> _resolvers;
    private readonly List<QuarantineItem> _quarantine;
    private readonly List<SystemSnapshot> _snapshots;

    private Timer? _feedTimer, _statsTimer, _promptTimer;
    private ProtectionMode _mode = ProtectionMode.Balanced;
    private DateTime? _updateWindowEnds;
    private long _telemetryBlocked = 18_342, _dnsBlocked = 52_117, _exeBlocked = 1_284;
    private double _etlMb = 1_236.4;
    private int _rules = 214, _latency = 12;
    private bool _realtime = true;
    private int _eventsWindow;
    private DateTime _windowStart = DateTime.UtcNow;
    private double _eps;
    private bool _promptPending;
    private DohResolver _resolver;
    private bool _dnssec = true, _dnssecStrict;

    public event EventHandler<FeedEvent>? FeedEventRaised;
    public event EventHandler<EngineStats>? StatsUpdated;
    public event EventHandler<ConnectionRequest>? ConnectionRequested;

    public SimulatedProtectionEngine(FilterListService filters)
    {
        _filters = filters;
        _apps = new List<AppRule>
        {
            App("brave.exe", @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe", "Brave Software, Inc.", 12),
            App("msedge.exe", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "Microsoft Corporation", 341),
            App("Discord.exe", @"C:\Users\Default\AppData\Local\Discord\app-1.0.9175\Discord.exe", "Discord Inc.", 88),
            App("Spotify.exe", @"C:\Users\Default\AppData\Roaming\Spotify\Spotify.exe", "Spotify AB", 205),
            App("steam.exe", @"C:\Program Files (x86)\Steam\steam.exe", "Valve Corp.", 47),
            App("Code.exe", @"C:\Users\Default\AppData\Local\Programs\Microsoft VS Code\Code.exe", "Microsoft Corporation", 63),
            App("OneDrive.exe", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "Microsoft Corporation", 512),
            App("SearchHost.exe", @"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe", "Microsoft Windows", 977, wan: false),
            App("WidgetService.exe", @"C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience\WidgetService.exe", "Microsoft Corporation", 1_420, wan: false, wifi: false, lan: false),
            App("CompatTelRunner.exe", @"C:\Windows\System32\CompatTelRunner.exe", "Microsoft Windows", 3_088, wan: false, wifi: false, lan: false),
            App("update_helper.exe", @"C:\Users\Public\AppData\Local\Temp\update_helper.exe", null, 19, wan: false, wifi: false, lan: false),
        };
        foreach (var a in _apps.Where(a => a.WanAllowed)) _approvedApps.Add(a.Name);
        _approvedApps.Add("ZeroLeakage.Core.exe");

        _resolvers = new List<DohResolver>
        {
            new("Cloudflare", "https://1.1.1.1/dns-query", "No-log · fastest anycast · DNSSEC", "Privacy"),
            new("Quad9", "https://dns.quad9.net/dns-query", "Malware filtering · Swiss · DNSSEC", "Security"),
            new("Mullvad", "https://dns.mullvad.net/dns-query", "No-log · Swedish · DNSSEC", "Privacy"),
            new("AdGuard DNS", "https://dns.adguard-dns.com/dns-query", "Blocks ads & trackers upstream too", "Filtering"),
            new("AdGuard Family", "https://family.adguard-dns.com/dns-query", "Ads + adult content + safe search", "Filtering"),
            new("Cloudflare Security", "https://security.cloudflare-dns.com/dns-query", "1.1.1.2 · blocks malware", "Security"),
            new("Cloudflare Family", "https://family.cloudflare-dns.com/dns-query", "1.1.1.3 · malware + adult", "Filtering"),
            new("Google Public DNS", "https://dns.google/dns-query", "Fast & reliable · logs kept 24–48 h", "Mainstream"),
            new("Control D (free)", "https://freedns.controld.com/p0", "Unfiltered · no-log · Canada", "Privacy"),
            new("DNS.SB", "https://doh.dns.sb/dns-query", "No-log · Germany", "Privacy"),
        };
        _resolver = _resolvers[0];

        // DeepScan is backed by Microsoft Defender (DefenderService); this engine holds no fake detections.
        _quarantine = new List<QuarantineItem>();

        _snapshots = new List<SystemSnapshot>
        {
            new(Guid.NewGuid(), "Pre-install baseline", DateTime.Now.AddDays(-12), "Automatic", 48_234_112),
            new(Guid.NewGuid(), "Before Strict Guard", DateTime.Now.AddDays(-3), "Manual", 51_002_890),
        };
    }

    private static AppRule App(string name, string path, string? publisher, long blocked, bool wan = true, bool wifi = true, bool lan = true)
        => new() { Name = name, Path = path, Publisher = publisher, IsSigned = publisher is not null, BlockedAttempts = blocked, WanAllowed = wan, WifiAllowed = wifi, LanAllowed = lan };

    private static string Hash(string seed) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(seed))).ToLowerInvariant();

    public ProtectionMode Mode { get { lock (_gate) return _mode; } }

    public void Start()
    {
        _feedTimer = new Timer(_ => SafeRun(Tick), null, 600, 140);
        _statsTimer = new Timer(_ => SafeRun(PublishStats), null, 0, 500);
        _promptTimer = new Timer(_ => SafeRun(MaybePrompt), null, 15_000, 9_000);
    }

    private static void SafeRun(Action a)
    {
        try { a(); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
    }

    // ───────────────────────── live feed ─────────────────────────
    private void Tick()
    {
        int count = _rng.Next(0, 3);
        for (int i = 0; i < count; i++)
        {
            FeedEvent ev;
            lock (_gate)
            {
                if (_updateWindowEnds is { } end && DateTime.Now >= end) _updateWindowEnds = null;
                var t = Templates[_rng.Next(Templates.Length)];
                ev = Decide(t);
                _eventsWindow++;
            }
            FeedEventRaised?.Invoke(this, ev);
        }
    }

    private FeedEvent Decide(Template t)
    {
        var now = DateTime.Now;
        FeedEvent Blocked(string category) => new(now, FeedVerdict.Blocked, t.Process, t.Service, t.Destination, t.Port, category);
        FeedEvent Allowed(string category) => new(now, FeedVerdict.Allowed, t.Process, t.Service, t.Destination, t.Port, category);

        var app = _apps.FirstOrDefault(a => a.Name.Equals(t.Process, StringComparison.OrdinalIgnoreCase));

        // Real filter lists decide first (your allowlist > your blocklist > @@ exceptions > list rules).
        var match = _filters.Match(t.Destination);
        if (match is { Blocked: true })
        {
            if (match.Category.Contains("Telemetry")) { _telemetryBlocked++; Bump(app); } else _dnsBlocked++;
            return Blocked(match.Category) with { Match = match };
        }
        bool allowlisted = match is { Blocked: false };

        if (_killedApps.Contains(t.Process) || app is { IsFullyKilled: true }) { _exeBlocked++; Bump(app); return Blocked("App Network Killed"); }
        if (!_globalScopes[NetworkScope.Wan] && t.Kind != Kind.Doh) { _exeBlocked++; return Blocked("WAN Kill-Switch"); }

        if (allowlisted && t.Kind is Kind.Telemetry or Kind.Tracker) return Allowed("Allowlisted") with { Match = match };

        switch (t.Kind)
        {
            case Kind.Telemetry:
                _telemetryBlocked++;
                if (_rng.NextDouble() < 0.08) _etlMb += _rng.NextDouble() * 0.6;
                Bump(app);
                return Blocked(t.Category);
            case Kind.Tracker:
                _dnsBlocked++;
                return Blocked(t.Category);
            case Kind.Doh:
                return Allowed(t.Category);
            case Kind.Update:
                if (_updateWindowEnds is not null) return Allowed("Update Window");
                if (_mode == ProtectionMode.Balanced) return Allowed(t.Category);
                _exeBlocked++;
                return Blocked("Update Deferred");
        }

        // Normal traffic
        if (_mode == ProtectionMode.TotalLockdown) { _exeBlocked++; Bump(app); return Blocked("Total Lockdown"); }
        if (app is { WanAllowed: false }) { _exeBlocked++; Bump(app); return Blocked("Firewall Rule"); }
        if (_mode == ProtectionMode.StrictGuard && !_approvedApps.Contains(t.Process)) { _exeBlocked++; return Blocked("Not Approved"); }
        return Allowed(t.Category);
    }

    private static void Bump(AppRule? app)
    {
        if (app is null) return;
        System.Windows.Application.Current?.Dispatcher.InvokeAsync(() => app.BlockedAttempts++);
    }

    private void PublishStats()
    {
        EngineStats s;
        lock (_gate)
        {
            var elapsed = (DateTime.UtcNow - _windowStart).TotalSeconds;
            if (elapsed >= 1)
            {
                _eps = _eventsWindow / elapsed;
                _eventsWindow = 0;
                _windowStart = DateTime.UtcNow;
            }
            _latency = Math.Clamp(_latency + _rng.Next(-2, 3), 8, 26);
            if (_updateWindowEnds is { } end && DateTime.Now >= end) _updateWindowEnds = null;
            // Antivirus figures are real: they come from Microsoft Defender via DefenderService.
            var av = DefenderService.LastStatus;
            int detections = DefenderService.LastDetections.Count(d => d.NeedsAction || d.IsQuarantined);
            s = new EngineStats(_telemetryBlocked, _etlMb, _dnsBlocked, _latency, _rules + _filters.TotalRules, _exeBlocked,
                av?.RealTimeProtection ?? false, av?.LastScan?.ToLocalTime(), detections, _eps, _updateWindowEnds);
        }
        StatsUpdated?.Invoke(this, s);
    }

    private void MaybePrompt()
    {
        ConnectionRequest? req = null;
        lock (_gate)
        {
            if (_mode != ProtectionMode.StrictGuard || _promptPending) return;
            var candidates = UnknownApps.Where(u => !_approvedApps.Contains(u.Name) && !_killedApps.Contains(u.Name)).ToArray();
            if (candidates.Length == 0 || _rng.NextDouble() > 0.6) return;
            var u = candidates[_rng.Next(candidates.Length)];
            _promptPending = true;
            req = new ConnectionRequest(Guid.NewGuid(), u.Name, u.Path, u.Publisher, u.Signed, u.Dest, u.Ip, 443, "TCP");
        }
        FeedEventRaised?.Invoke(this, new FeedEvent(DateTime.Now, FeedVerdict.Prompted, req.ProcessName, null, req.Destination, req.Port, "Ask to Connect"));
        ConnectionRequested?.Invoke(this, req);
    }

    // ───────────────────────── commands ─────────────────────────
    public Task SetModeAsync(ProtectionMode mode)
    {
        lock (_gate)
        {
            _mode = mode;
            _rules = mode switch { ProtectionMode.Balanced => 214, ProtectionMode.StrictGuard => 388, _ => 1_024 };
            if (mode == ProtectionMode.StrictGuard) _promptTimer?.Change(3_500, 9_000);
        }
        return Task.CompletedTask;
    }

    public Task SubmitDecisionAsync(ConnectionRequest request, ConnectDecision decision)
    {
        FeedEvent ev;
        lock (_gate)
        {
            _promptPending = false;
            switch (decision)
            {
                case ConnectDecision.Allow:
                    _approvedApps.Add(request.ProcessName);
                    _rules++;
                    if (_apps.All(a => !a.Name.Equals(request.ProcessName, StringComparison.OrdinalIgnoreCase)))
                    {
                        var rule = new AppRule { Name = request.ProcessName, Path = request.ProcessPath, Publisher = request.Publisher, IsSigned = request.IsSigned };
                        _apps.Add(rule);
                    }
                    break;
                case ConnectDecision.Block:
                    _killedApps.Add(request.ProcessName);
                    _rules++;
                    _exeBlocked++;
                    break;
            }
            ev = new FeedEvent(DateTime.Now, decision == ConnectDecision.Block ? FeedVerdict.Blocked : FeedVerdict.Allowed,
                request.ProcessName, null, request.Destination, request.Port,
                decision switch { ConnectDecision.Allow => "User Allowed", ConnectDecision.AllowOnce => "Allowed Once", _ => "User Blocked" });
        }
        FeedEventRaised?.Invoke(this, ev);
        return Task.CompletedTask;
    }

    // Your own block/allow domains live in the shared filter service (called on the UI thread).
    public Task BlockDomainAsync(string domain) { _filters.Block(domain); return Task.CompletedTask; }
    public Task UnblockDomainAsync(string domain) { _filters.RemoveBlock(domain); return Task.CompletedTask; }

    public Task KillAppNetworkAsync(string processName)
    {
        lock (_gate)
        {
            if (_killedApps.Add(processName)) _rules += 3;
            _approvedApps.Remove(processName);
        }
        return Task.CompletedTask;
    }

    public Task SetAppAccessAsync(AppRule app, NetworkScope scope, bool allowed)
    {
        lock (_gate)
        {
            if (allowed) _killedApps.Remove(app.Name);
            if (scope == NetworkScope.Wan)
            {
                if (allowed) _approvedApps.Add(app.Name); else _approvedApps.Remove(app.Name);
            }
        }
        return Task.CompletedTask;
    }

    public Task SetGlobalScopeAsync(NetworkScope scope, bool allowed) { lock (_gate) _globalScopes[scope] = allowed; return Task.CompletedTask; }

    public Task<DateTime> OpenUpdateWindowAsync(TimeSpan duration)
    {
        lock (_gate) { _updateWindowEnds = DateTime.Now + duration; return Task.FromResult(_updateWindowEnds.Value); }
    }

    public Task CloseUpdateWindowAsync() { lock (_gate) _updateWindowEnds = null; return Task.CompletedTask; }

    public async Task RestoreDefaultsAsync()
    {
        await Task.Delay(1_200);
        lock (_gate)
        {
            _mode = ProtectionMode.Balanced;
            _blockedDomains.Clear();
            _killedApps.Clear();
            _updateWindowEnds = null;
            _rules = 214;
            _dnssec = true;
            _dnssecStrict = false;
            foreach (var k in _globalScopes.Keys.ToList()) _globalScopes[k] = true;
        }
        await _filters.RestoreDefaultsAsync();
    }

    public IReadOnlyList<AppRule> GetAppRules() { lock (_gate) return _apps.ToList(); }
    public IReadOnlyList<BlocklistSource> GetBlocklists() => _filters.Lists;
    public IReadOnlyList<DohResolver> GetResolvers() => _resolvers;

    public IReadOnlyList<TelemetryServiceStatus> GetTelemetryServices() => new[]
    {
        new TelemetryServiceStatus("DiagTrack", "Connected User Experiences and Telemetry", true),
        new TelemetryServiceStatus("dmwappushservice", "Device Management WAP Push", true),
        new TelemetryServiceStatus("WerSvc", "Windows Error Reporting", true),
        new TelemetryServiceStatus("PcaSvc", "Program Compatibility Assistant", false),
        new TelemetryServiceStatus("WdiSystemHost", "Diagnostic System Host", false),
    };

    public Task SetBlocklistEnabledAsync(BlocklistSource list, bool enabled) => _filters.SetEnabledAsync(list, enabled);
    public Task SetResolverAsync(DohResolver resolver) { lock (_gate) _resolver = resolver; return Task.CompletedTask; }
    public DohResolver CurrentResolver { get { lock (_gate) return _resolver; } }
    public bool DnssecEnabled { get { lock (_gate) return _dnssec; } }
    public bool DnssecStrict { get { lock (_gate) return _dnssecStrict; } }
    public Task SetDnssecAsync(bool enabled, bool strict) { lock (_gate) { _dnssec = enabled; _dnssecStrict = enabled && strict; } return Task.CompletedTask; }

    public async Task<double> WipeTraceLogsAsync(IProgress<double>? progress, CancellationToken ct = default)
    {
        for (int i = 1; i <= 40; i++)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(45, ct);
            progress?.Report(i / 40d * 100);
        }
        double mb = Math.Round(140 + _rng.NextDouble() * 280, 1);
        lock (_gate) _etlMb += mb;
        return mb;
    }

    public Task SetRealtimeProtectionAsync(bool enabled) { lock (_gate) _realtime = enabled; return Task.CompletedTask; }

    /// <summary>Not used by the UI any more: DeepScan talks to Microsoft Defender directly (DefenderService).</summary>
    public Task<ScanResult> RunScanAsync(ScanKind kind, IProgress<ScanProgress> progress, CancellationToken ct) =>
        Task.FromException<ScanResult>(new NotSupportedException("DeepScan runs through Microsoft Defender (DefenderService)."));

    public IReadOnlyList<QuarantineItem> GetQuarantine() { lock (_gate) return _quarantine.ToList(); }
    public Task RestoreQuarantinedAsync(QuarantineItem item) { lock (_gate) _quarantine.RemoveAll(q => q.Id == item.Id); return Task.CompletedTask; }
    public Task DeleteQuarantinedAsync(QuarantineItem item) { lock (_gate) _quarantine.RemoveAll(q => q.Id == item.Id); return Task.CompletedTask; }

    public IReadOnlyList<SystemSnapshot> GetSnapshots() { lock (_gate) return _snapshots.ToList(); }

    public async Task<SystemSnapshot> CreateSnapshotAsync(string name)
    {
        await Task.Delay(1_400);
        var s = new SystemSnapshot(Guid.NewGuid(), string.IsNullOrWhiteSpace(name) ? $"Manual snapshot {DateTime.Now:dd MMM HH:mm}" : name.Trim(),
            DateTime.Now, "Manual", 47_000_000 + _rng.Next(0, 6_000_000));
        lock (_gate) _snapshots.Insert(0, s);
        return s;
    }

    public Task RestoreSnapshotAsync(SystemSnapshot snapshot) => Task.Delay(1_800);

    public async Task<AuditReport> RunAuditAsync(IProgress<AuditProgress> progress, CancellationToken ct = default)
    {
        string[] stages =
        {
            "Enumerating telemetry services (DiagTrack, dmwappushservice)…",
            "Reading AllowTelemetry & advertising-ID policies…",
            "Inspecting DNS client — resolver & DoH state…",
            "Auditing Windows Firewall outbound defaults…",
            "Measuring .etl trace logs in %ProgramData%\\Microsoft\\Diagnosis…",
            "Checking scheduled tasks: CEIP, Compatibility Appraiser…",
            "Checking Defender & real-time protection state…",
            "Building privacy scorecard…",
        };
        for (int i = 0; i < stages.Length; i++)
        {
            for (int j = 0; j < 10; j++)
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(70, ct);
                progress.Report(new AuditProgress((i * 10 + j + 1) * 100d / (stages.Length * 10), stages[i]));
            }
        }

        var categories = new List<AuditCategory>
        {
            new("OS Telemetry", "DiagTrack running · AllowTelemetry = 3 (Full)", AuditSeverity.Critical),
            new("Advertising ID", "Enabled for 14 apps", AuditSeverity.Critical),
            new("DNS Privacy", "Plain-text DNS to ISP resolver", AuditSeverity.Critical),
            new("Firewall Outbound", "Default ALLOW for all executables", AuditSeverity.Warning),
            new("Trace Logs", "412 MB of .etl diagnostics on disk", AuditSeverity.Warning),
            new("Real-time AV", "Defender active · signatures current", AuditSeverity.Good),
        };
        var recs = new List<AuditRecommendation>
        {
            new() { Id = "telemetry", Title = "Disable OS telemetry", Description = "Stops DiagTrack & dmwappushservice and sets AllowTelemetry to Security.", ImpactTag = "No impact", Impact = ImpactLevel.None, ScoreGain = 18 },
            new() { Id = "doh", Title = "Encrypt all DNS (DoH)", Description = "Routes every lookup through an encrypted resolver; ISP sees nothing.", ImpactTag = "No impact", Impact = ImpactLevel.None, ScoreGain = 14 },
            new() { Id = "adid", Title = "Kill advertising ID", Description = "Resets and disables the per-user advertising identifier.", ImpactTag = "No impact", Impact = ImpactLevel.None, ScoreGain = 8 },
            new() { Id = "firewall", Title = "Outbound firewall lockdown", Description = "Creates the ZeroLeakage_Core rule group; unknown apps must ask first.", ImpactTag = "Apps may ask once", Impact = ImpactLevel.Low, ScoreGain = 12 },
            new() { Id = "etl", Title = "Wipe & cap trace logs", Description = "Deletes existing .etl traces and caps AutoLogger sessions.", ImpactTag = "No impact", Impact = ImpactLevel.None, ScoreGain = 6 },
            new() { Id = "bing", Title = "Remove Bing from Start search", Description = "Start-menu search stays local; no keystrokes leave the PC.", ImpactTag = "No web results in Start", Impact = ImpactLevel.Low, ScoreGain = 5 },
            new() { Id = "widgets", Title = "Disable Widgets & news feed", Description = "Removes the MSN widget board and its background traffic.", ImpactTag = "Widgets board removed", Impact = ImpactLevel.Medium, ScoreGain = 3 },
        };
        return new AuditReport(34, categories, recs);
    }

    public async Task ApplyRecommendationsAsync(IEnumerable<AuditRecommendation> recommendations)
    {
        int n = recommendations.Count();
        await Task.Delay(600 + n * 250);
        lock (_gate) _rules += n * 9;
    }

    public void Dispose()
    {
        _feedTimer?.Dispose();
        _statsTimer?.Dispose();
        _promptTimer?.Dispose();
    }
}
