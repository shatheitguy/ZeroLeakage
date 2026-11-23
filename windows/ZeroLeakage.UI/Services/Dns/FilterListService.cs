using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.ViewModels;

namespace ZeroLeakage.UI.Services.Dns;

/// <summary>
/// Real filter-list subscriptions for the Windows app: downloads lists into
/// %LocalAppData%\ZeroLeakage\filters, counts rules, and keeps a <see cref="FilterIndex"/> the engine
/// can match domains against. State (enabled set, timestamps, custom lists, allow/block) persists as JSON.
/// </summary>
public sealed class FilterListService
{
    private const string Hagezi = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock";
    private const string SB = "https://raw.githubusercontent.com/StevenBlack/hosts/master";
    private const long MaxBytes = 64L * 1024 * 1024;
    public static readonly TimeSpan AutoUpdateAge = TimeSpan.FromDays(3);

    public static readonly string[] GroupOrder =
        { "Built-in (offline)", "Ads & trackers", "All-in-one", "Privacy & telemetry", "Security", "Parental & focus", "Custom lists" };

    private static readonly HttpClient Http = CreateHttp();
    private readonly string _dir = Path.Combine(UiSettingsStore.Directory, "filters");
    private string StatePath => Path.Combine(_dir, "state.json");
    private readonly SemaphoreSlim _rebuildGate = new(1, 1);
    private volatile FilterIndex _index = FilterIndex.Empty;
    private int _rebuildPending;

    public ObservableCollection<BlocklistSource> Lists { get; } = new();
    public ObservableCollection<string> UserAllow { get; } = new();
    public ObservableCollection<string> UserBlock { get; } = new();

    public event EventHandler? IndexRebuilt;
    /// <summary>True while defaults are being restored (bulk IsEnabled changes shouldn't each trigger work).</summary>
    public bool IsRestoring { get; private set; }
    public int TotalRules => _index.TotalRules;

    private static HttpClient CreateHttp()
    {
        var h = new HttpClient(new HttpClientHandler { AutomaticDecompression = System.Net.DecompressionMethods.All })
        { Timeout = TimeSpan.FromSeconds(90) };
        h.DefaultRequestHeaders.UserAgent.ParseAdd("ZeroLeakage-Windows/1.1");
        return h;
    }

    public FilterListService()
    {
        foreach (var l in Catalog()) Lists.Add(l);
        Load();
    }

    private static IEnumerable<BlocklistSource> Catalog()
    {
        BlocklistSource L(string id, string name, string desc, string group, string cat, string? url, string approx, string? home = null, bool on = false, string? embedded = null)
            => new() { Id = id, Name = name, Description = desc, Group = group, Category = cat, Url = url, ApproxRules = approx, Homepage = home, DefaultOn = on, Embedded = embedded };
        const string hz = "https://github.com/hagezi/dns-blocklists";
        const string sbh = "https://github.com/StevenBlack/hosts";
        return new[]
        {
            L("win_telemetry", "Windows Telemetry Core", "DiagTrack, Watson, CEIP, settings-win and Bing/MSN feed endpoints.", GroupOrder[0], "OS Telemetry", null, "", on: true, embedded: BuiltIn.WindowsTelemetry),
            L("analytics_sdk", "App Analytics SDKs", "Sentry, Mixpanel, Segment, Amplitude, Firebase/Google Analytics.", GroupOrder[0], "Analytics", null, "", on: true, embedded: BuiltIn.Analytics),

            L("adguard_dns", "AdGuard DNS filter", "AdGuard's DNS-optimised list: ads, trackers, analytics. Low false positives.", GroupOrder[1], "Ad Tracker",
                "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "~190K", "https://github.com/AdguardTeam/AdGuardSDNSFilter", on: true),
            L("adaway", "AdAway default", "Classic ad-server hosts file.", GroupOrder[1], "Ad Tracker", "https://adaway.org/hosts.txt", "~6K", "https://adaway.org"),
            L("pgl", "Peter Lowe's list", "Hand-curated ad and tracking servers.", GroupOrder[1], "Ad Tracker",
                "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "~3K", "https://pgl.yoyo.org/adservers/"),
            L("easyprivacy", "EasyPrivacy", "Tracking-only list from the EasyList authors (domain rules only).", GroupOrder[1], "Ad Tracker",
                "https://easylist.to/easylist/easyprivacy.txt", "~47K", "https://easylist.to"),
            L("hagezi_popup", "HaGeZi Pop-Up Ads", "Malicious pop-up, pop-under and redirect ad networks.", GroupOrder[1], "Ad Tracker", $"{Hagezi}/popupads.txt", "~60K", hz),
            L("someonewhocares", "Dan Pollock's hosts", "Ads, banners, tracking and shock sites.", GroupOrder[1], "Ad Tracker", "https://someonewhocares.org/hosts/zero/hosts", "~12K", "https://someonewhocares.org/hosts/"),

            L("oisd_small", "OISD Small", "Ads, trackers and malware with almost zero breakage.", GroupOrder[2], "Ad Tracker", "https://small.oisd.nl/", "~60K", "https://oisd.nl"),
            L("oisd_big", "OISD Big", "OISD's full list — bigger coverage, still tuned for no false positives.", GroupOrder[2], "Ad Tracker", "https://big.oisd.nl/", "~200K", "https://oisd.nl"),
            L("hagezi_light", "HaGeZi Light", "Basic protection: ads, tracking, metrics.", GroupOrder[2], "Ad Tracker", $"{Hagezi}/light.txt", "~90K", hz),
            L("hagezi_multi", "HaGeZi Multi Normal", "Ads, affiliate, tracking, metrics, telemetry, phishing, malware.", GroupOrder[2], "Ad Tracker", $"{Hagezi}/multi.txt", "~200K", hz),
            L("hagezi_pro", "HaGeZi Multi PRO", "Extended protection; HaGeZi's recommendation for most users.", GroupOrder[2], "Ad Tracker", $"{Hagezi}/pro.txt", "~250K", hz),
            L("stevenblack", "StevenBlack Unified hosts", "Consolidated hosts from AdAway, Dan Pollock, URLhaus and more.", GroupOrder[2], "Ad Tracker", $"{SB}/hosts", "~76K", sbh),

            L("hagezi_winoffice", "Native tracker: Windows & Office", "HaGeZi list of Windows / Office telemetry endpoints.", GroupOrder[3], "OS Telemetry", $"{Hagezi}/native.winoffice.txt", "~400", hz),
            L("windowsspyblocker", "WindowsSpyBlocker (spy)", "Microsoft telemetry hosts captured by WindowsSpyBlocker.", GroupOrder[3], "OS Telemetry",
                "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", "~350", "https://github.com/crazy-max/WindowsSpyBlocker"),
            L("hagezi_amazon", "Native tracker: Amazon", "Amazon device and app metrics.", GroupOrder[3], "App Telemetry", $"{Hagezi}/native.amazon.txt", "~400", hz),
            L("hagezi_apple", "Native tracker: Apple", "Apple analytics endpoints (iTunes, iCloud for Windows).", GroupOrder[3], "App Telemetry", $"{Hagezi}/native.apple.txt", "~100", hz),
            L("hagezi_tiktok", "Native tracker: TikTok", "TikTok analytics and fingerprinting.", GroupOrder[3], "App Telemetry", $"{Hagezi}/native.tiktok.txt", "~600", hz),

            L("hagezi_tif_mini", "HaGeZi Threat Intelligence (mini)", "Malware, phishing, scam, crypto-jacking and C2 domains.", GroupOrder[4], "Malware", $"{Hagezi}/tif.mini.txt", "~150K", hz),
            L("urlhaus", "URLhaus malware filter", "Malware distribution hosts from abuse.ch URLhaus.", GroupOrder[4], "Malware",
                "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt", "~10K", "https://gitlab.com/malware-filter/urlhaus-filter"),
            L("phishing_army", "Phishing Army", "Phishing domains from PhishTank, OpenPhish and others.", GroupOrder[4], "Malware",
                "https://phishing.army/download/phishing_army_blocklist.txt", "~140K", "https://phishing.army"),
            L("nocoin", "NoCoin", "Browser crypto-mining scripts.", GroupOrder[4], "Malware",
                "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", "~400", "https://github.com/hoshsadiq/adblock-nocoin-list"),

            L("sb_gambling", "Gambling", "Betting and casino sites (StevenBlack alternate).", GroupOrder[5], "Gambling", $"{SB}/alternates/gambling-only/hosts", "~5K", sbh),
            L("sb_adult", "Adult content", "Pornography sites (StevenBlack alternate).", GroupOrder[5], "Adult", $"{SB}/alternates/porn-only/hosts", "~70K", sbh),
            L("sb_social", "Social media", "Facebook, Instagram, TikTok, X, Reddit… for focus time.", GroupOrder[5], "Social", $"{SB}/alternates/social-only/hosts", "~3K", sbh),
        };
    }

    // ───────────────────────── matching ─────────────────────────
    /// <summary>
    /// Order: the server admin's locked blocks → your allow → your block → server-managed allow/block
    /// (blocked services, categories…) → filter lists. "Bypass blocking" from the server turns matching off.
    /// </summary>
    public FilterMatch? Match(string domain)
    {
        var m = _managed;
        if (m.Bypass) return null;
        var d = domain.ToLowerInvariant().TrimEnd('.');
        if (m.LockedBlock.Count > 0 && FindSuffix(d, m.LockedBlock) is { } locked)
            return new FilterMatch(true, "server_locked", $"Set by admin · {m.ManagedBy}", "Network policy", $"||{locked}^", locked);
        var hit = _index.Match(d);
        if (hit is { ListId: "user_allow" or "user_block" }) return hit;
        if (m.Allow.Count > 0 && FindSuffix(d, m.Allow) is { } a)
            return new FilterMatch(false, "server_allow", $"Managed by {m.ManagedBy}", "Allowlisted", $"@@||{a}^", a);
        if (m.Block.Count > 0 && FindSuffix(d, m.Block) is { } b)
            return new FilterMatch(true, "server_block", $"Managed by {m.ManagedBy}", "Server policy", $"||{b}^", b);
        return hit;
    }

    private static string? FindSuffix(string d, HashSet<string> set)
    {
        for (var s = d; ; )
        {
            if (set.Contains(s)) return s;
            int dot = s.IndexOf('.');
            if (dot < 0 || dot == s.Length - 1) return null;
            s = s[(dot + 1)..];
        }
    }

    // ───────────────────────── ZeroLeakage Server management ─────────────────────────
    private sealed record ManagedState(string ManagedBy, HashSet<string> LockedBlock, HashSet<string> Allow, HashSet<string> Block, bool Bypass,
        ZeroLeakage.Shared.Link.PolicyLocks Locks)
    {
        public static readonly ManagedState None = new("", new(), new(), new(), false, ZeroLeakage.Shared.Link.PolicyLocks.None);
    }

    private volatile ManagedState _managed = ManagedState.None;

    /// <summary>Raised when the user edits rules or lists (not when sync applies the server's state).</summary>
    public event EventHandler? LocalChanged;
    /// <summary>Raised after sync applied or removed server management.</summary>
    public event EventHandler? ManagedChanged;

    public bool IsManaged => _managed.ManagedBy.Length > 0;
    public string ManagedBy => _managed.ManagedBy;
    public bool BypassBlocking => _managed.Bypass;
    public ObservableCollection<string> LockedBlockDomains { get; } = new();
    public int ManagedBlockCount => _managed.Block.Count;

    /// <summary>Null when the domain may be allowed; otherwise the "Set by admin" explanation.</summary>
    public string? AllowLockReason(string raw)
    {
        var d = FilterParser.Normalize(raw);
        if (d is null) return null;
        return _managed.Locks.CanAllow(d, out var reason) ? null : reason;
    }

    public void NotifyLocalListChange()
    {
        if (!IsRestoring) LocalChanged?.Invoke(this, EventArgs.Empty);
    }

    public ZeroLeakage.Shared.Link.LocalProtectionSnapshot Snapshot() => new()
    {
        EnabledLists = Lists.Where(l => !l.IsCustom && l.IsEnabled).Select(l => l.Id).ToList(),
        CustomLists = Lists.Where(l => l.IsCustom).Select(l => new ZeroLeakage.Shared.Link.CustomListSpec
        {
            Url = l.Url ?? "", Name = l.Name, Category = l.Category, Enabled = l.IsEnabled, Locked = l.IsLocked,
        }).ToList(),
        Allow = UserAllow.ToList(),
        Block = UserBlock.ToList(),
    };

    /// <summary>Makes this PC an exact clone of the plan (must run on the UI thread).</summary>
    public async Task ApplyManagedAsync(ZeroLeakage.Shared.Link.SyncPlan plan)
    {
        ApplyState(plan.EnabledLists, plan.LockedLists, plan.CustomLists, plan.Allow, plan.Block);
        _managed = new ManagedState(plan.ManagedBy,
            new HashSet<string>(plan.LockedBlockDomains, StringComparer.Ordinal),
            new HashSet<string>(plan.ManagedAllow, StringComparer.Ordinal),
            new HashSet<string>(plan.ManagedBlock, StringComparer.Ordinal),
            plan.BypassBlocking, plan.Locks);
        Replace(LockedBlockDomains, plan.LockedBlockDomains);
        Save();
        ManagedChanged?.Invoke(this, EventArgs.Empty);
        IndexRebuilt?.Invoke(this, EventArgs.Empty);
        _ = StartAsync();   // downloads newly enabled lists in the background; sync doesn't wait for them
        await Task.CompletedTask;
    }

    /// <summary>Unlink: back to the PC's own protection from before linking, nothing managed or locked.</summary>
    public async Task RestoreLocalAsync(ZeroLeakage.Shared.Link.LocalProtectionSnapshot s)
    {
        ApplyState(new HashSet<string>(s.EnabledLists, StringComparer.OrdinalIgnoreCase), new HashSet<string>(),
            s.CustomLists.Select(c => new ZeroLeakage.Shared.Link.CustomListSpec { Url = c.Url, Name = c.Name, Category = c.Category, Enabled = c.Enabled }).ToList(),
            s.Allow, s.Block);
        _managed = ManagedState.None;
        LockedBlockDomains.Clear();
        Save();
        ManagedChanged?.Invoke(this, EventArgs.Empty);
        IndexRebuilt?.Invoke(this, EventArgs.Empty);
        _ = StartAsync();   // downloads newly enabled lists in the background; sync doesn't wait for them
        await Task.CompletedTask;
    }

    private void ApplyState(ISet<string> enabled, ISet<string> locked, IReadOnlyList<ZeroLeakage.Shared.Link.CustomListSpec> custom,
        IReadOnlyList<string> allow, IReadOnlyList<string> block)
    {
        IsRestoring = true;
        try
        {
            var wanted = custom.Where(c => c.Url.Length > 0).GroupBy(c => c.Url, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
            foreach (var l in Lists.Where(l => l.IsCustom && (l.Url is null || !wanted.ContainsKey(l.Url))).ToList())
            {
                Lists.Remove(l);
                try { File.Delete(FileFor(l.Id)); } catch { /* ignore */ }
            }
            foreach (var c in wanted.Values)
            {
                var l = Lists.FirstOrDefault(x => x.IsCustom && string.Equals(x.Url, c.Url, StringComparison.OrdinalIgnoreCase));
                if (l is null)
                {
                    l = new BlocklistSource
                    {
                        Id = CustomId(c.Url), Name = c.Name, Description = c.Url, Group = "Custom lists",
                        Category = string.IsNullOrWhiteSpace(c.Category) ? "Custom List" : c.Category, Url = c.Url, IsCustom = true,
                    };
                    Lists.Add(l);
                }
                l.IsEnabled = c.Enabled;
                l.IsLocked = c.Locked;
            }
            foreach (var l in Lists.Where(l => !l.IsCustom))
            {
                l.IsEnabled = enabled.Contains(l.Id);
                l.IsLocked = locked.Contains(l.Id);
            }
            Replace(UserAllow, allow);
            Replace(UserBlock, block);
        }
        finally { IsRestoring = false; }
        _index = _index.WithUser(UserAllow, UserBlock);
    }

    private static void Replace(ObservableCollection<string> target, IEnumerable<string> items)
    {
        var list = items.ToList();
        if (target.SequenceEqual(list)) return;
        target.Clear();
        foreach (var i in list) target.Add(i);
    }

    private static string CustomId(string url) =>
        "custom_" + Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(System.Text.Encoding.UTF8.GetBytes(url)))[..8].ToLowerInvariant();

    // ───────────────────────── subscriptions ─────────────────────────
    public async Task SetEnabledAsync(BlocklistSource list, bool on)
    {
        if (list.IsLocked && !on) return;   // set by the server admin
        list.IsEnabled = on;
        NotifyLocalListChange();
        Save();
        if (on && !list.IsBundled && !File.Exists(FileFor(list.Id))) await DownloadAsync(list);
        else await RebuildAsync();
    }

    public Task UpdateAsync(BlocklistSource list) => DownloadAsync(list);

    public async Task UpdateAllAsync()
    {
        foreach (var l in Lists.Where(l => l.IsEnabled && !l.IsBundled).ToList()) await DownloadAsync(l, rebuild: false);
        await RebuildAsync();
    }

    /// <summary>Fetches never-downloaded enabled lists and refreshes ones older than 3 days, then builds the index.</summary>
    public async Task StartAsync()
    {
        foreach (var l in Lists.Where(l => l.IsEnabled && !l.IsBundled).ToList())
        {
            if (!File.Exists(FileFor(l.Id)) || l.UpdatedAt is null || DateTime.Now - l.UpdatedAt > AutoUpdateAge)
                await DownloadAsync(l, rebuild: false);
        }
        await RebuildAsync();
    }

    public async Task<string?> AddCustomAsync(string rawUrl, string rawName)
    {
        var url = rawUrl.Trim();
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "https" && uri.Scheme != "http")) return "Enter an http(s):// URL";
        if (Lists.Any(l => string.Equals(l.Url, url, StringComparison.OrdinalIgnoreCase))) return "That list is already added";
        var list = new BlocklistSource
        {
            Id = "custom_" + Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(System.Text.Encoding.UTF8.GetBytes(url)))[..8].ToLowerInvariant(),
            Name = string.IsNullOrWhiteSpace(rawName) ? uri.Host : rawName.Trim(),
            Description = url, Group = "Custom lists", Category = "Custom List", Url = url, IsCustom = true,
        };
        Lists.Add(list);
        await SetEnabledAsync(list, true);
        NotifyLocalListChange();
        return list.Error;
    }

    public async Task RemoveCustomAsync(BlocklistSource list)
    {
        if (!list.IsCustom || list.IsLocked) return;
        Lists.Remove(list);
        try { File.Delete(FileFor(list.Id)); } catch { /* ignore */ }
        Save();
        NotifyLocalListChange();
        await RebuildAsync();
    }

    // ───────────────────────── your allow / block lists ─────────────────────────
    public string? Allow(string raw) => AddUser(raw, UserAllow, UserBlock);
    public string? Block(string raw) => AddUser(raw, UserBlock, UserAllow);
    public void RemoveAllow(string d) { UserAllow.Remove(d); UserChanged(); }
    public void RemoveBlock(string d) { UserBlock.Remove(d); UserChanged(); }

    private string? AddUser(string raw, ObservableCollection<string> into, ObservableCollection<string> other)
    {
        var d = FilterParser.Normalize(raw);
        if (d is null) return null;
        if (into == UserAllow && AllowLockReason(d) is not null) return null;   // admin baseline can't be unblocked
        other.Remove(d);
        if (!into.Contains(d)) into.Insert(0, d);
        UserChanged();
        return d;
    }

    private void UserChanged()
    {
        _index = _index.WithUser(UserAllow, UserBlock);
        Save();
        IndexRebuilt?.Invoke(this, EventArgs.Empty);
        if (!IsRestoring) LocalChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task RestoreDefaultsAsync()
    {
        IsRestoring = true;
        try
        {
            foreach (var l in Lists.Where(l => l.IsCustom).ToList()) Lists.Remove(l);
            foreach (var l in Lists) l.IsEnabled = l.DefaultOn;
            UserAllow.Clear();
            UserBlock.Clear();
        }
        finally { IsRestoring = false; }
        Save();
        await StartAsync();
    }

    // ───────────────────────── download ─────────────────────────
    private string FileFor(string id) => Path.Combine(_dir, id + ".txt");

    private async Task DownloadAsync(BlocklistSource list, bool rebuild = true)
    {
        if (list.Url is null) return;
        Ui.Post(() => { list.IsDownloading = true; list.Error = null; });
        var target = FileFor(list.Id);
        var tmp = target + ".tmp";
        try
        {
            Directory.CreateDirectory(_dir);
            using (var resp = await Http.GetAsync(list.Url, HttpCompletionOption.ResponseHeadersRead))
            {
                if (!resp.IsSuccessStatusCode) throw new InvalidOperationException($"HTTP {(int)resp.StatusCode}");
                await using var input = await resp.Content.ReadAsStreamAsync();
                await using var output = File.Create(tmp);
                var buf = new byte[81920];
                long total = 0;
                int n;
                while ((n = await input.ReadAsync(buf)) > 0)
                {
                    total += n;
                    if (total > MaxBytes) throw new InvalidOperationException("List is larger than 64 MB");
                    await output.WriteAsync(buf.AsMemory(0, n));
                }
            }
            int rules = await Task.Run(() => File.ReadLines(tmp).Count(l => FilterParser.ParseLine(l) is not null));
            if (rules == 0) throw new InvalidOperationException("No usable DNS rules in this list");
            File.Move(tmp, target, overwrite: true);
            var bytes = new FileInfo(target).Length;
            Ui.Post(() => { list.RuleCount = rules; list.Bytes = bytes; list.UpdatedAt = DateTime.Now; list.IsDownloading = false; });
            Save();
            if (rebuild) await RebuildAsync();
        }
        catch (Exception ex)
        {
            try { File.Delete(tmp); } catch { /* ignore */ }
            var msg = ex is TaskCanceledException ? "Timed out" : ex.Message;
            Ui.Post(() => { list.IsDownloading = false; list.Error = msg; });
        }
    }

    // ───────────────────────── index ─────────────────────────
    public async Task RebuildAsync()
    {
        if (Interlocked.Exchange(ref _rebuildPending, 1) == 1) return;     // one queued rebuild is enough
        await _rebuildGate.WaitAsync();
        try
        {
            Interlocked.Exchange(ref _rebuildPending, 0);
            var snapshot = Lists.Where(l => l.IsEnabled).ToList();
            var allow = UserAllow.ToList();
            var block = UserBlock.ToList();
            var (index, counts) = await Task.Run(() =>
            {
                var b = new FilterIndex.Builder();
                var c = new Dictionary<BlocklistSource, int>();
                foreach (var l in snapshot)
                {
                    var label = new FilterIndex.Label(l.Id, l.Name, l.Category);
                    if (l.Embedded is not null) c[l] = b.AddList(label, l.Embedded.Split('\n'), plainIsSuffix: true);
                    else if (File.Exists(FileFor(l.Id))) c[l] = b.AddList(label, File.ReadLines(FileFor(l.Id)));
                }
                return (b.User(allow, block).Build(), c);
            });
            _index = index;
            Ui.Post(() => { foreach (var (l, n) in counts) l.RuleCount = n; });
            IndexRebuilt?.Invoke(this, EventArgs.Empty);
        }
        finally { _rebuildGate.Release(); }
    }

    // ───────────────────────── persistence ─────────────────────────
    private sealed class State
    {
        public List<string> Enabled { get; set; } = new();
        public Dictionary<string, DateTime> Updated { get; set; } = new();
        public List<CustomList> Custom { get; set; } = new();
        public List<string> Allow { get; set; } = new();
        public List<string> Block { get; set; } = new();
        public Managed? Server { get; set; }
    }

    /// <summary>Last state applied from a linked ZeroLeakage Server (kept so protection holds offline / before the first sync).</summary>
    private sealed class Managed
    {
        public string ManagedBy { get; set; } = "";
        public List<string> LockedLists { get; set; } = new();
        public List<string> LockedBlock { get; set; } = new();
        public List<string> Allow { get; set; } = new();
        public List<string> Block { get; set; } = new();
        public bool Bypass { get; set; }
    }

    private sealed class CustomList
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Url { get; set; } = "";
        public bool Locked { get; set; }
    }

    private void Load()
    {
        State? st = null;
        try { if (File.Exists(StatePath)) st = JsonSerializer.Deserialize<State>(File.ReadAllText(StatePath)); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }

        if (st is null)
        {
            foreach (var l in Lists) l.IsEnabled = l.DefaultOn;
            return;
        }
        foreach (var c in st.Custom)
            Lists.Add(new BlocklistSource { Id = c.Id, Name = c.Name, Description = c.Url, Group = "Custom lists", Category = "Custom List", Url = c.Url, IsCustom = true, IsLocked = c.Locked });
        foreach (var l in Lists)
        {
            l.IsEnabled = st.Enabled.Contains(l.Id);
            if (st.Updated.TryGetValue(l.Id, out var t) && File.Exists(FileFor(l.Id)))
            {
                l.UpdatedAt = t;
                l.Bytes = new FileInfo(FileFor(l.Id)).Length;
            }
        }
        foreach (var d in st.Allow) UserAllow.Add(d);
        foreach (var d in st.Block) UserBlock.Add(d);
        if (st.Server is { ManagedBy.Length: > 0 } m)
        {
            foreach (var l in Lists.Where(l => !l.IsCustom)) l.IsLocked = m.LockedLists.Contains(l.Id);
            var locks = new ZeroLeakage.Shared.Link.PolicyLocks(m.LockedLists, Array.Empty<string>(), Array.Empty<string>(), m.LockedBlock, m.ManagedBy);
            _managed = new ManagedState(m.ManagedBy, new HashSet<string>(m.LockedBlock), new HashSet<string>(m.Allow), new HashSet<string>(m.Block), m.Bypass, locks);
            foreach (var d in m.LockedBlock) LockedBlockDomains.Add(d);
        }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(_dir);
            var st = new State
            {
                Enabled = Lists.Where(l => l.IsEnabled).Select(l => l.Id).ToList(),
                Updated = Lists.Where(l => l.UpdatedAt is not null).ToDictionary(l => l.Id, l => l.UpdatedAt!.Value),
                Custom = Lists.Where(l => l.IsCustom).Select(l => new CustomList { Id = l.Id, Name = l.Name, Url = l.Url!, Locked = l.IsLocked }).ToList(),
                Allow = UserAllow.ToList(),
                Block = UserBlock.ToList(),
                Server = _managed.ManagedBy.Length == 0 ? null : new Managed
                {
                    ManagedBy = _managed.ManagedBy,
                    LockedLists = Lists.Where(l => !l.IsCustom && l.IsLocked).Select(l => l.Id).ToList(),
                    LockedBlock = _managed.LockedBlock.ToList(),
                    Allow = _managed.Allow.ToList(),
                    Block = _managed.Block.ToList(),
                    Bypass = _managed.Bypass,
                },
            };
            File.WriteAllText(StatePath, JsonSerializer.Serialize(st, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
    }

    private static class BuiltIn
    {
        public const string WindowsTelemetry = """
            vortex.data.microsoft.com
            vortex-win.data.microsoft.com
            settings-win.data.microsoft.com
            v10.events.data.microsoft.com
            v20.events.data.microsoft.com
            self.events.data.microsoft.com
            events.data.microsoft.com
            watson.telemetry.microsoft.com
            watson.microsoft.com
            telemetry.microsoft.com
            oca.telemetry.microsoft.com
            sqm.telemetry.microsoft.com
            telecommand.telemetry.microsoft.com
            umwatson.events.data.microsoft.com
            ceuswatcab01.blob.core.windows.net
            browser.events.data.msn.com
            browser.pipe.aria.microsoft.com
            mobile.pipe.aria.microsoft.com
            dc.services.visualstudio.com
            nav.smartscreen.microsoft.com
            """;

        public const string Analytics = """
            sentry.io
            app-measurement.com
            google-analytics.com
            ssl.google-analytics.com
            analytics.google.com
            api.mixpanel.com
            api-js.mixpanel.com
            api.segment.io
            cdn.segment.com
            api.amplitude.com
            api2.amplitude.com
            stats.g.doubleclick.net
            api.bugsnag.com
            sessions.bugsnag.com
            in.appcenter.ms
            api.instabug.com
            """;
    }
}
