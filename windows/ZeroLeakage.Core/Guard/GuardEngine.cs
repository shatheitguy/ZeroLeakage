using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using ZeroLeakage.Core.Dns;
using ZeroLeakage.Shared.Ipc;
using ZeroLeakage.Shared.Link;

namespace ZeroLeakage.Core.Guard;

public sealed record OpResult(bool Ok, string? Error = null, string? Message = null)
{
    public static OpResult Success(string? message = null) => new(true, null, message);
    public static OpResult Fail(string error) => new(false, error);
}

/// <summary>
/// Guard: a local CrowdSec-style engine. Threat-IP feeds + behaviour scenarios produce decisions; everything that is
/// blocked is enforced by Windows Firewall rules in the "ZeroLeakage Guard" group. The never-ban allowlist
/// (reserved ranges, this PC's addresses, gateways, DNS servers, the linked server, manual entries) always wins.
/// </summary>
public sealed class GuardEngine : IDisposable
{
    public const string ScenarioBruteForce = "brute-force";
    public const string ScenarioPortScan = "port-scan";
    public const string ScenarioManual = "manual";
    private const int MaxAlerts = 200;
    private const int MaxManualAllow = 1000;

    private readonly GuardPaths _paths;
    private readonly IFirewall _firewall;
    private readonly IFeedSource _source;
    private readonly ILocalNetworkInfo _network;
    private readonly TimeProvider _clock;
    private readonly ILogger _log;
    private readonly GuardFirewallSync _sync;
    private readonly DnsModeManager _dns;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolve;
    private readonly object _lock = new();
    private readonly SemaphoreSlim _syncGate = new(1, 1), _feedGate = new(1, 1), _signal = new(0, 1);

    private GuardConfig _config = new();
    private DecisionFile _decisions = new();
    private Dictionary<string, FeedState> _feedStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, IReadOnlyList<IpRange>> _feedRanges = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (bool Available, string? Note)> _scenarioAvailability = new()
    {
        [ScenarioBruteForce] = (false, "Starting…"),
        [ScenarioPortScan] = (false, "Starting…"),
    };
    private BruteForceDetector _bruteForce = new(5, TimeSpan.FromMinutes(10));
    private PortScanDetector _portScan = new(15, TimeSpan.FromMinutes(1));
    private IReadOnlyList<IPAddress> _serverIps = Array.Empty<IPAddress>();
    private IpRangeSet _enforced = IpRangeSet.Empty;
    private DateTimeOffset _startedAt;
    private DateTimeOffset? _lastSync;
    private int _ruleCount;
    private bool? _firewallOn;
    private string? _lastSyncError;
    private volatile bool _syncRequested, _updatingFeeds;
    private bool _initialized;

    public GuardEngine(GuardPaths paths, IFirewall firewall, IFeedSource source, ILocalNetworkInfo network, IDnsConfigurator dns,
        TimeProvider clock, ILogger<GuardEngine> log, Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null)
    {
        _paths = paths;
        _firewall = firewall;
        _source = source;
        _network = network;
        _clock = clock;
        _log = log;
        _sync = new GuardFirewallSync(firewall);
        _dns = new DnsModeManager(dns, paths.DnsBackupFile, clock);
        _resolve = resolver ?? ((host, ct) => System.Net.Dns.GetHostAddressesAsync(host, ct));
    }

    public static string Version => typeof(GuardEngine).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    public bool IsUpdatingFeeds => _updatingFeeds;
    public DnsModeManager DnsMode => _dns;

    // ───────────────────────── lifecycle ─────────────────────────

    public void Initialize()
    {
        lock (_lock)
        {
            if (_initialized) return;
            _paths.EnsureCreated();
            _config = JsonStore.Load<GuardConfig>(_paths.ConfigFile) ?? new GuardConfig();
            foreach (var f in FeedCatalog.Builtin) _config.Feeds.TryAdd(f.Id, f.DefaultEnabled);
            _decisions = JsonStore.Load<DecisionFile>(_paths.DecisionsFile) ?? new DecisionFile();
            _feedStates = JsonStore.Load<Dictionary<string, FeedState>>(_paths.FeedStateFile) is { } fs
                ? new Dictionary<string, FeedState>(fs, StringComparer.OrdinalIgnoreCase)
                : new(StringComparer.OrdinalIgnoreCase);
            foreach (var feed in AllFeedsLocked())
            {
                var cache = _paths.FeedCache(feed.Id);
                if (!File.Exists(cache)) continue;
                try { _feedRanges[feed.Id] = FeedParser.Parse(File.ReadAllText(cache)).Ranges; }
                catch (IOException ex) { _log.LogWarning(ex, "Couldn't read cached feed {Feed}", feed.Id); }
            }
            RebuildDetectorsLocked();
            ExpireLocked(_clock.GetUtcNow());
            SaveConfigLocked();
            SaveDecisionsLocked();
            _startedAt = _clock.GetUtcNow();
            _initialized = true;
        }
        _network.Changed += (_, _) => RequestSync();
        _ = ResolveServerAsync(CancellationToken.None);
    }

    /// <summary>Background loop: debounced firewall syncs, expiry every 30 s, feed check every hour (daily refresh).</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        Initialize();
        await SyncFirewallAsync(ct).ConfigureAwait(false);
        var nextExpiry = _clock.GetUtcNow();
        var nextFeedCheck = _clock.GetUtcNow().AddSeconds(20);
        while (!ct.IsCancellationRequested)
        {
            try { await _signal.WaitAsync(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            try
            {
                if (_syncRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
                    await SyncFirewallAsync(ct).ConfigureAwait(false);
                }
                var now = _clock.GetUtcNow();
                if (now >= nextExpiry)
                {
                    ExpireDecisions();
                    lock (_lock) { _bruteForce.Prune(now); _portScan.Prune(now); }
                    nextExpiry = now.AddSeconds(30);
                }
                if (now >= nextFeedCheck)
                {
                    nextFeedCheck = now.AddHours(1);
                    bool enabled;
                    lock (_lock) enabled = _config.Enabled;
                    if (enabled) await UpdateFeedsAsync(force: false, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogError(ex, "Guard loop error"); }
        }
    }

    /// <summary>Asks the background loop for a (debounced) firewall sync.</summary>
    public void RequestSync()
    {
        _syncRequested = true;
        if (_signal.CurrentCount == 0)
        {
            try { _signal.Release(); } catch (SemaphoreFullException) { }
        }
    }

    // ───────────────────────── enforcement ─────────────────────────

    /// <summary>Computes the blocked set (feeds + bans − allowlist) and applies it diff-style to Windows Firewall.</summary>
    public async Task SyncFirewallAsync(CancellationToken ct = default)
    {
        await _syncGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            IpRangeSet feeds, bans, allow;
            lock (_lock)
            {
                _syncRequested = false;
                allow = BuildAllowlistLocked();
                if (_config.Enabled)
                {
                    feeds = IpRangeSet.Create(_feedRanges.Where(kv => IsFeedEnabledLocked(kv.Key)).SelectMany(kv => kv.Value));
                    bans = IpRangeSet.Create(ActiveBansLocked().Select(d => IpRange.TryParse(d.Value, out var r) ? r : (IpRange?)null).OfType<IpRange>());
                }
                else feeds = bans = IpRangeSet.Empty;
            }
            feeds = feeds.Subtract(allow);
            bans = bans.Subtract(allow);
            var chunks = GuardFirewallSync.BuildChunks("Feeds", feeds).Concat(GuardFirewallSync.BuildChunks("Bans", bans)).ToList();
            var result = await Task.Run(() => _sync.Apply(chunks), ct).ConfigureAwait(false);
            var count = await Task.Run(() => _firewall.GetRules(GuardFirewallSync.Group).Count, ct).ConfigureAwait(false);
            var fwOn = _firewall.IsEnabledForCurrentProfiles();
            lock (_lock)
            {
                _enforced = feeds.Union(bans);
                _ruleCount = count;
                _firewallOn = fwOn;
                _lastSync = _clock.GetUtcNow();
                _lastSyncError = result.Failed > 0 ? $"{result.Failed} stale firewall rule(s) couldn't be removed" : null;
            }
            if (result.Added + result.Removed > 0)
                _log.LogInformation("Guard firewall sync: +{Added} -{Removed} ={Kept} rules, {Entries} entries", result.Added, result.Removed, result.Kept, feeds.Count + bans.Count);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            lock (_lock) _lastSyncError = "Couldn't update Windows Firewall: " + ex.Message;
            _log.LogError(ex, "Guard firewall sync failed");
        }
        finally { _syncGate.Release(); }
    }

    /// <summary>Removes every Guard rule from Windows Firewall.</summary>
    public int Cleanup() => _sync.Cleanup();

    private IpRangeSet BuildAllowlistLocked()
    {
        var extra = new List<IpRange>();
        foreach (var ip in _network.GetProtectedAddresses().Concat(_serverIps)) extra.Add(IpRange.FromAddress(ip));
        foreach (var e in _config.Allowlist) if (IpRange.TryParse(e, out var r)) extra.Add(r);
        return ReservedRanges.Set.Union(IpRangeSet.Create(extra));
    }

    public bool IsAllowlisted(IPAddress ip)
    {
        lock (_lock) return BuildAllowlistLocked().Contains(ip);
    }

    /// <summary>True if the address is currently enforced (feeds or bans, after the allowlist).</summary>
    public bool IsBlocked(IPAddress ip)
    {
        lock (_lock) return _enforced.Contains(ip);
    }

    // ───────────────────────── feeds ─────────────────────────

    private IEnumerable<FeedDefinition> AllFeedsLocked()
    {
        foreach (var f in FeedCatalog.Builtin) yield return f;
        if (_config.Server.IsConfigured && SecretProtector.Unprotect(_config.Server.ProtectedKey) is { } key)
            yield return FeedCatalog.ServerFeed(new Uri(_config.Server.Url!), key, _config.Server.ServerName ?? new Uri(_config.Server.Url!).Host);
    }

    private bool IsFeedEnabledLocked(string id) =>
        id.Equals(FeedCatalog.ServerFeedId, StringComparison.OrdinalIgnoreCase)
            ? _config.Server.IsConfigured && _config.ServerFeedEnabled
            : _config.Feeds.TryGetValue(id, out var on) && on;

    private FeedState StateLocked(string id)
    {
        if (!_feedStates.TryGetValue(id, out var st)) _feedStates[id] = st = new FeedState();
        return st;
    }

    /// <summary>Downloads enabled feeds older than the refresh interval (all of them when <paramref name="force"/>).</summary>
    public async Task<OpResult> UpdateFeedsAsync(bool force, CancellationToken ct = default, string? onlyFeed = null)
    {
        await _feedGate.WaitAsync(ct).ConfigureAwait(false);
        _updatingFeeds = true;
        try
        {
            List<FeedDefinition> feeds;
            TimeSpan refresh;
            lock (_lock)
            {
                feeds = AllFeedsLocked().Where(f => IsFeedEnabledLocked(f.Id) && (onlyFeed is null || f.Id.Equals(onlyFeed, StringComparison.OrdinalIgnoreCase))).ToList();
                refresh = TimeSpan.FromHours(Math.Clamp(_config.FeedRefreshHours, 1, 24 * 7));
            }
            int ok = 0, failed = 0, skipped = 0;
            foreach (var feed in feeds)
            {
                string? etag, lastModified;
                lock (_lock)
                {
                    var st = StateLocked(feed.Id);
                    var fresh = st.LastSuccess is { } t && _clock.GetUtcNow() - t < refresh && _feedRanges.ContainsKey(feed.Id);
                    if (!force && fresh) { skipped++; continue; }
                    bool haveCache = _feedRanges.ContainsKey(feed.Id) && File.Exists(_paths.FeedCache(feed.Id));
                    etag = haveCache ? st.ETag : null;
                    lastModified = haveCache ? st.LastModified : null;
                }

                var res = await _source.FetchAsync(feed, etag, lastModified, ct).ConfigureAwait(false);
                FeedParseResult? parsed = res.Status == FetchStatus.Updated ? FeedParser.Parse(res.Text ?? "") : null;
                lock (_lock)
                {
                    var st = StateLocked(feed.Id);
                    st.LastAttempt = _clock.GetUtcNow();
                    switch (res.Status)
                    {
                        case FetchStatus.Updated when parsed!.Accepted == 0 && parsed.Invalid > 0:
                            st.LastError = "The download didn't contain IP addresses";
                            failed++;
                            break;
                        case FetchStatus.Updated:
                            try { File.WriteAllText(_paths.FeedCache(feed.Id), res.Text); }
                            catch (IOException ex) { _log.LogWarning(ex, "Couldn't cache feed {Feed}", feed.Id); }
                            _feedRanges[feed.Id] = parsed!.Ranges;
                            st.Entries = parsed.Accepted;
                            st.Skipped = parsed.SkippedReserved;
                            st.Invalid = parsed.Invalid + parsed.TooBroad;
                            st.ETag = res.ETag;
                            st.LastModified = res.LastModified;
                            st.LastSuccess = st.LastAttempt;
                            st.LastError = null;
                            ok++;
                            break;
                        case FetchStatus.NotModified:
                            st.LastSuccess = st.LastAttempt;
                            st.LastError = null;
                            ok++;
                            break;
                        default:
                            st.LastError = res.Error ?? "Download failed";
                            failed++;
                            break;
                    }
                }
                if (res.Status == FetchStatus.Failed) _log.LogWarning("Guard feed {Feed} failed: {Error}", feed.Id, res.Error);
            }
            lock (_lock) SaveFeedStatesLocked();
            RequestSync();
            return OpResult.Success(failed == 0
                ? $"{ok + skipped} feed(s) up to date"
                : $"{ok + skipped} feed(s) up to date, {failed} failed");
        }
        finally
        {
            _updatingFeeds = false;
            _feedGate.Release();
        }
    }

    /// <summary>Starts a feed update without waiting (IPC "update now").</summary>
    public Task StartFeedUpdate(bool force, string? onlyFeed = null) => Task.Run(async () =>
    {
        try { await UpdateFeedsAsync(force, CancellationToken.None, onlyFeed).ConfigureAwait(false); }
        catch (Exception ex) { _log.LogError(ex, "Guard feed update failed"); }
    });

    public OpResult SetFeedEnabled(string id, bool enabled)
    {
        bool needDownload;
        lock (_lock)
        {
            if (id.Equals(FeedCatalog.ServerFeedId, StringComparison.OrdinalIgnoreCase))
            {
                if (!_config.Server.IsConfigured) return OpResult.Fail("No ZeroLeakage Server is configured");
                if (_config.PolicyManaged && _config.Server.IsLinked) return OpResult.Fail($"Managed by {ServerNameLocked()}");
                _config.ServerFeedEnabled = enabled;
            }
            else
            {
                if (FeedCatalog.Find(id) is null) return OpResult.Fail("Unknown feed");
                _config.Feeds[id] = enabled;
            }
            SaveConfigLocked();
            needDownload = enabled && !_feedRanges.ContainsKey(id);
        }
        if (needDownload) _ = StartFeedUpdate(force: false, onlyFeed: id);
        RequestSync();
        return OpResult.Success();
    }

    // ───────────────────────── decisions ─────────────────────────

    private IEnumerable<Decision> ActiveBansLocked()
    {
        var now = _clock.GetUtcNow();
        return _decisions.Bans.Where(d => d.ExpiresAt is null || d.ExpiresAt > now);
    }

    public OpResult Ban(string? value, string? reason, double? hours)
    {
        if (!IpRange.TryParse(value, out var r)) return OpResult.Fail("Enter an IP address or CIDR range, like 203.0.113.7 or 198.51.100.0/24");
        if (FeedParser.IsTooBroad(r)) return OpResult.Fail("That range is too large to ban");
        if (hours is < 0 or > 24 * 365) return OpResult.Fail("Ban duration must be up to a year");
        var canonical = r.ToString();
        lock (_lock)
        {
            var allow = BuildAllowlistLocked();
            if (allow.ContainsRange(r))
                return OpResult.Fail($"{canonical} is on the never-ban allowlist (your LAN, this PC, its gateway/DNS, or an address you allowed)");
            var now = _clock.GetUtcNow();
            _decisions.Bans.RemoveAll(d => d.Value == canonical);
            _decisions.Bans.Add(new Decision
            {
                Value = canonical,
                Reason = string.IsNullOrWhiteSpace(reason) ? "Manual ban" : Trim(reason, 200),
                Scenario = ScenarioManual,
                Source = "manual",
                CreatedAt = now,
                ExpiresAt = hours is > 0 ? now.AddHours(hours.Value) : null,
            });
            SaveDecisionsLocked();
        }
        RequestSync();
        return OpResult.Success($"Banned {canonical}");
    }

    public OpResult Unban(string? value)
    {
        if (!IpRange.TryParse(value, out var r)) return OpResult.Fail("Enter an IP address or CIDR range");
        var canonical = r.ToString();
        bool stillListed;
        lock (_lock)
        {
            int removed = _decisions.Bans.RemoveAll(d => d.Value == canonical || d.Id == value);
            if (removed == 0) return OpResult.Fail($"No active ban for {canonical}");
            SaveDecisionsLocked();
            stillListed = _config.Enabled && _feedRanges.Where(kv => IsFeedEnabledLocked(kv.Key)).Any(kv => kv.Value.Any(x => x.Overlaps(r)));
        }
        RequestSync();
        return OpResult.Success(stillListed
            ? $"Unbanned {canonical}. It's still on a threat feed — use Allow IP to override the feed."
            : $"Unbanned {canonical}");
    }

    public OpResult Allow(string? value)
    {
        if (!IpRange.TryParse(value, out var r)) return OpResult.Fail("Enter an IP address or CIDR range to allow");
        var canonical = r.ToString();
        lock (_lock)
        {
            if (_config.Allowlist.Count >= MaxManualAllow) return OpResult.Fail("The allowlist is full");
            if (!_config.Allowlist.Contains(canonical)) _config.Allowlist.Add(canonical);
            _decisions.Bans.RemoveAll(d => IpRange.TryParse(d.Value, out var b) && r.Contains(b));
            SaveConfigLocked();
            SaveDecisionsLocked();
        }
        RequestSync();
        return OpResult.Success($"{canonical} will never be blocked");
    }

    public OpResult RemoveAllow(string? value)
    {
        var canonical = IpRange.TryParse(value, out var r) ? r.ToString() : value?.Trim() ?? "";
        lock (_lock)
        {
            if (_config.Allowlist.RemoveAll(e => e == canonical) == 0) return OpResult.Fail("Not on the manual allowlist");
            SaveConfigLocked();
        }
        RequestSync();
        return OpResult.Success($"Removed {canonical} from the allowlist");
    }

    /// <summary>Drops expired bans; returns how many.</summary>
    public int ExpireDecisions()
    {
        int n;
        lock (_lock)
        {
            n = ExpireLocked(_clock.GetUtcNow());
            if (n > 0) SaveDecisionsLocked();
        }
        if (n > 0) RequestSync();
        return n;
    }

    private int ExpireLocked(DateTimeOffset now) => _decisions.Bans.RemoveAll(d => d.ExpiresAt is { } e && e <= now);

    // ───────────────────────── detection ─────────────────────────

    /// <summary>Windows Security event 4625 (failed logon).</summary>
    public void OnFailedLogon(string? ipText, string? user, DateTimeOffset? when = null)
    {
        if (!TryClientIp(ipText, out var ip)) return;
        lock (_lock)
        {
            if (!_config.Enabled || !_config.BruteForce.Enabled) return;
            var hit = _bruteForce.Record(ip, when ?? _clock.GetUtcNow());
            if (hit is null) return;
            RaiseLocked(ip, ScenarioBruteForce,
                $"{hit.Events} failed Windows sign-ins in {Minutes(_bruteForce.Window)} (RDP/SMB brute force)", hit.Events, _config.BruteForce.BanHours);
        }
    }

    /// <summary>A dropped unsolicited inbound packet from the Windows Firewall log.</summary>
    public void OnDroppedInbound(string? ipText, int port, DateTimeOffset? when = null)
    {
        if (!TryClientIp(ipText, out var ip) || port <= 0) return;
        lock (_lock)
        {
            if (!_config.Enabled || !_config.PortScan.Enabled) return;
            if (ReservedRanges.Set.Contains(ip) || _enforced.Contains(ip)) return;   // LAN chatter / already blocked
            var hit = _portScan.Record(ip, port, when ?? _clock.GetUtcNow());
            if (hit is null) return;
            RaiseLocked(ip, ScenarioPortScan, $"{hit.Events} different ports probed in {Minutes(_portScan.Window)} (port scan)", hit.Events,
                _config.PortScan.BanHours);
        }
    }

    private void RaiseLocked(IPAddress ip, string scenario, string message, int events, double banHours)
    {
        var now = _clock.GetUtcNow();
        var value = IpRange.FromAddress(ip).ToString();
        bool allowlisted = BuildAllowlistLocked().Contains(ip);
        bool alreadyBanned = ActiveBansLocked().Any(d => IpRange.TryParse(d.Value, out var r) && r.Contains(IpRange.FromAddress(ip)));
        bool banned = false;
        if (!allowlisted && !alreadyBanned)
        {
            _decisions.Bans.Add(new Decision
            {
                Value = value,
                Reason = message,
                Scenario = scenario,
                Source = "local",
                CreatedAt = now,
                ExpiresAt = now.AddHours(Math.Clamp(banHours, 0.1, 24 * 30)),
                Events = events,
            });
            banned = true;
        }
        _decisions.Alerts.Add(new AlertRecord
        {
            Time = now,
            Value = value,
            Scenario = scenario,
            Message = allowlisted ? message + " — on the allowlist, not banned" : alreadyBanned ? message + " — already banned" : message,
            Events = events,
            Banned = banned,
        });
        if (_decisions.Alerts.Count > MaxAlerts) _decisions.Alerts.RemoveRange(0, _decisions.Alerts.Count - MaxAlerts);
        SaveDecisionsLocked();
        _log.LogWarning("Guard {Scenario}: {Ip} {Message} banned={Banned}", scenario, value, message, banned);
        if (banned) RequestSync();
    }

    private static bool TryClientIp(string? text, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (string.IsNullOrWhiteSpace(text) || text.Trim() == "-") return false;
        if (!IpRange.TryParseAddress(text, out var parsed)) return false;
        ip = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        return true;
    }

    public void SetScenarioAvailability(string id, bool available, string? note)
    {
        lock (_lock) _scenarioAvailability[id] = (available, note);
    }

    public OpResult SetScenarioEnabled(string id, bool enabled)
    {
        lock (_lock)
        {
            var sc = id switch { ScenarioBruteForce => _config.BruteForce, ScenarioPortScan => _config.PortScan, _ => null };
            if (sc is null) return OpResult.Fail("Unknown scenario");
            sc.Enabled = enabled;
            RebuildDetectorsLocked();
            SaveConfigLocked();
        }
        return OpResult.Success();
    }

    private void RebuildDetectorsLocked()
    {
        _bruteForce = new BruteForceDetector(_config.BruteForce.Threshold, TimeSpan.FromMinutes(_config.BruteForce.WindowMinutes));
        _portScan = new PortScanDetector(_config.PortScan.Threshold, TimeSpan.FromMinutes(_config.PortScan.WindowMinutes));
    }

    // ───────────────────────── switches, server link, DNS ─────────────────────────

    public OpResult SetEnabled(bool enabled)
    {
        lock (_lock)
        {
            if (_config.PolicyManaged && _config.Server.IsLinked) return OpResult.Fail($"Guard is managed by {ServerNameLocked()}");
            if (_config.Enabled == enabled) return OpResult.Success();
            _config.Enabled = enabled;
            SaveConfigLocked();
        }
        RequestSync();
        if (enabled) _ = StartFeedUpdate(force: false);
        return OpResult.Success(enabled ? "Guard on" : "Guard off — its firewall rules are removed");
    }

    /// <summary>Manual bouncer mode: the Guard page's server URL + bouncer API key. Empty URL clears it.</summary>
    public OpResult SetServer(string? url, string? key)
    {
        lock (_lock)
        {
            if (_config.Server.IsLinked)
                return OpResult.Fail($"Guard already uses your linked server ({ServerNameLocked()}). Unlink it in Account & sync first.");
            if (string.IsNullOrWhiteSpace(url))
            {
                _config.Server = new ServerConfig();
                ForgetServerFeedLocked();
                SaveConfigLocked();
                RequestSync();
                return OpResult.Success("Server bouncer off");
            }
            if (!ServerAddress.TryNormalize(url, out var uri, out var err, out _)) return OpResult.Fail(err!);
            var normalized = uri!.AbsoluteUri.TrimEnd('/');
            bool sameUrl = normalized == _config.Server.Url;
            if (string.IsNullOrWhiteSpace(key) && !(sameUrl && _config.Server.ProtectedKey is not null))
                return OpResult.Fail("Enter the bouncer API key from your server");
            if (key is { Length: > 4096 } || (key?.IndexOfAny(new[] { '\r', '\n' }) ?? -1) >= 0) return OpResult.Fail("That API key isn't valid");
            if (!sameUrl) ForgetServerFeedLocked();
            _config.Server = new ServerConfig
            {
                Url = normalized,
                ProtectedKey = string.IsNullOrWhiteSpace(key) ? _config.Server.ProtectedKey : SecretProtector.Protect(key.Trim()),
                Source = "manual",
                ServerName = uri.Host,
            };
            _config.ServerFeedEnabled = true;
            _config.PolicyManaged = false;
            SaveConfigLocked();
        }
        _ = ResolveServerAsync(CancellationToken.None);
        _ = StartFeedUpdate(force: true, onlyFeed: FeedCatalog.ServerFeedId);
        return OpResult.Success("Server bouncer saved");
    }

    /// <summary>Account &amp; sync linked this PC: the device token becomes Guard's bouncer key.</summary>
    public OpResult SetLink(string? url, string? token, string? serverName, string? deviceId, string? dohUrl)
    {
        if (!ServerAddress.TryNormalize(url, out var uri, out var err, out _)) return OpResult.Fail(err!);
        if (string.IsNullOrWhiteSpace(token) || token.Length > 4096 || token.IndexOfAny(new[] { '\r', '\n' }) >= 0)
            return OpResult.Fail("Missing device token");
        var normalized = uri!.AbsoluteUri.TrimEnd('/');
        bool changed, dohChanged;
        lock (_lock)
        {
            var s = _config.Server;
            bool sameServer = s.IsLinked && s.Url == normalized && SecretProtector.Unprotect(s.ProtectedKey) == token.Trim();
            dohChanged = s.DohUrl != dohUrl;
            changed = !sameServer || s.ServerName != serverName || s.DeviceId != deviceId || dohChanged;
            if (!changed) return OpResult.Success();
            if (!sameServer) ForgetServerFeedLocked();
            _config.Server = new ServerConfig
            {
                Url = normalized,
                ProtectedKey = sameServer ? s.ProtectedKey : SecretProtector.Protect(token.Trim()),
                Source = "link",
                ServerName = string.IsNullOrWhiteSpace(serverName) ? uri.Host : Trim(serverName, 100),
                DeviceId = deviceId,
                DohUrl = dohUrl,
            };
            if (!sameServer) _config.ServerFeedEnabled = true;
            SaveConfigLocked();
        }
        _ = ResolveServerAsync(CancellationToken.None);
        _ = StartFeedUpdate(force: true, onlyFeed: FeedCatalog.ServerFeedId);
        if (dohChanged && _dns.IsEnabled) _ = Task.Run(() => SetDnsModeAsync(true, CancellationToken.None));
        return OpResult.Success("Linked");
    }

    /// <summary>Unlink: forget the server, give Guard back to the user and put Windows DNS back.</summary>
    public OpResult ClearLink()
    {
        var dns = _dns.Disable();
        lock (_lock)
        {
            if (_config.Server.IsLinked)
            {
                _config.Server = new ServerConfig();
                ForgetServerFeedLocked();
            }
            _config.PolicyManaged = false;
            SaveConfigLocked();
            _serverIps = Array.Empty<IPAddress>();
        }
        RequestSync();
        return dns.Ok ? OpResult.Success("Unlinked") : OpResult.Fail(dns.Error!);
    }

    /// <summary>The linked server's Guard policy (admin baseline): Guard on/off and its blocklist on/off.</summary>
    public OpResult SetGuardPolicy(bool enabled, bool dropMaliciousIps)
    {
        bool changed;
        lock (_lock)
        {
            if (!_config.Server.IsLinked) return OpResult.Fail("Not linked to a server");
            changed = _config.Enabled != enabled || _config.ServerFeedEnabled != dropMaliciousIps || !_config.PolicyManaged;
            _config.Enabled = enabled;
            _config.ServerFeedEnabled = dropMaliciousIps;
            _config.PolicyManaged = true;
            if (changed) SaveConfigLocked();
        }
        if (changed) RequestSync();
        return OpResult.Success();
    }

    public async Task<OpResult> SetDnsModeAsync(bool enabled, CancellationToken ct)
    {
        if (!enabled)
        {
            var off = _dns.Disable();
            return off.Ok ? OpResult.Success("Windows DNS restored") : OpResult.Fail(off.Error!);
        }
        string url;
        string? doh;
        lock (_lock)
        {
            if (!_config.Server.IsLinked) return OpResult.Fail("Link this PC to a server in Account & sync first");
            url = _config.Server.Url!;
            doh = _config.Server.DohUrl;
        }
        if (string.IsNullOrWhiteSpace(doh)) return OpResult.Fail("The server didn't give this device a DNS-over-HTTPS address");
        var ip = await ResolveServerIpAsync(new Uri(url), ct).ConfigureAwait(false);
        if (ip is null) return OpResult.Fail("Couldn't find the server's IP address");
        var on = _dns.Enable(ip.ToString(), doh);
        return on.Ok ? OpResult.Success($"Windows now resolves through {ip}") : OpResult.Fail(on.Error!);
    }

    private async Task<IPAddress?> ResolveServerIpAsync(Uri server, CancellationToken ct)
    {
        if (IPAddress.TryParse(server.Host.Trim('[', ']'), out var literal)) return literal;
        try
        {
            var all = await _resolve(server.Host, ct).ConfigureAwait(false);
            return all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? all.FirstOrDefault();
        }
        catch (SocketException) { return null; }
    }

    /// <summary>The configured server's own addresses are never banned (Guard must not cut off its bouncer).</summary>
    private async Task ResolveServerAsync(CancellationToken ct)
    {
        string? url;
        lock (_lock) url = _config.Server.Url;
        if (url is null) return;
        var host = new Uri(url).Host.Trim('[', ']');
        IPAddress[] ips;
        try { ips = IPAddress.TryParse(host, out var lit) ? new[] { lit } : await _resolve(host, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is SocketException or ArgumentException) { return; }
        lock (_lock) _serverIps = ips.Select(i => i.IsIPv4MappedToIPv6 ? i.MapToIPv4() : i).ToList();
        RequestSync();
    }

    private void ForgetServerFeedLocked()
    {
        _feedRanges.Remove(FeedCatalog.ServerFeedId);
        _feedStates.Remove(FeedCatalog.ServerFeedId);
        try { File.Delete(_paths.FeedCache(FeedCatalog.ServerFeedId)); } catch (IOException) { }
        SaveFeedStatesLocked();
    }

    private string ServerNameLocked() => _config.Server.ServerName ?? "your ZeroLeakage Server";

    // ───────────────────────── read side ─────────────────────────

    public GuardStatusDto GetStatus()
    {
        _dns.IsSupported(out var dnsWhy);
        var backup = _dns.Backup;
        lock (_lock)
        {
            var status = new GuardStatusDto
            {
                Running = true,
                Version = Version,
                StartedAt = _startedAt,
                Enabled = _config.Enabled,
                UpdatingFeeds = _updatingFeeds,
                LastFeedUpdate = _feedStates.Where(kv => IsFeedEnabledLocked(kv.Key)).Select(kv => kv.Value.LastSuccess).Max(),
                LastSync = _lastSync,
                BlockedEntries = _enforced.Count,
                BlockedIPv4Addresses = (long)UInt128.Min(_enforced.AddressCount(IpFamily.V4), (UInt128)long.MaxValue),
                FirewallRules = _ruleCount,
                FirewallEnabled = _firewallOn,
                ActiveBans = ActiveBansLocked().Count(),
                LastError = _lastSyncError,
                Server = new GuardServerDto
                {
                    Configured = _config.Server.IsConfigured,
                    Url = _config.Server.Url,
                    KeySet = _config.Server.ProtectedKey is not null,
                    Linked = _config.Server.IsLinked,
                    ServerName = _config.Server.ServerName,
                    PolicyManaged = _config.PolicyManaged && _config.Server.IsLinked,
                },
                Dns = new DnsModeDto
                {
                    Enabled = backup is not null,
                    Available = dnsWhy is null && _config.Server.IsLinked && !string.IsNullOrWhiteSpace(_config.Server.DohUrl),
                    ServerIp = backup?.ServerIp,
                    DohTemplate = backup?.DohTemplate ?? _config.Server.DohUrl,
                    Note = dnsWhy,
                    LastError = _dns.LastError,
                    Adapters = backup?.Adapters.Count ?? 0,
                },
            };
            foreach (var f in AllFeedsLocked())
            {
                var st = _feedStates.TryGetValue(f.Id, out var s) ? s : new FeedState();
                status.Feeds.Add(new GuardFeedDto
                {
                    Id = f.Id,
                    Name = f.Name,
                    Description = f.Description,
                    Homepage = f.IsServer ? null : f.Homepage,
                    Enabled = IsFeedEnabledLocked(f.Id),
                    IsServer = f.IsServer,
                    LastUpdated = st.LastSuccess,
                    Entries = _feedRanges.TryGetValue(f.Id, out var r) ? r.Count : 0,
                    Skipped = st.Skipped,
                    LastError = st.LastError,
                });
            }
            status.Scenarios.Add(Scenario(ScenarioBruteForce, "Brute-force sign-ins",
                $"{_config.BruteForce.Threshold} failed Windows sign-ins (RDP, SMB…) from one address within {Minutes(TimeSpan.FromMinutes(_config.BruteForce.WindowMinutes))} → ban for {_config.BruteForce.BanHours:0.#} h.",
                _config.BruteForce));
            status.Scenarios.Add(Scenario(ScenarioPortScan, "Port scans",
                $"{_config.PortScan.Threshold} different closed ports probed within {Minutes(TimeSpan.FromMinutes(_config.PortScan.WindowMinutes))} → ban for {_config.PortScan.BanHours:0.#} h. Needs Windows Firewall logging of dropped packets.",
                _config.PortScan));
            return status;
        }
    }

    private GuardScenarioDto Scenario(string id, string name, string description, ScenarioConfig cfg)
    {
        var (available, note) = _scenarioAvailability.TryGetValue(id, out var a) ? a : (false, null);
        return new GuardScenarioDto { Id = id, Name = name, Description = description, Enabled = cfg.Enabled, Available = available, Note = note };
    }

    public List<GuardDecisionDto> GetDecisions()
    {
        lock (_lock)
            return ActiveBansLocked().OrderByDescending(d => d.CreatedAt).Select(d => new GuardDecisionDto
            {
                Id = d.Id, Value = d.Value, Type = d.Type, Reason = d.Reason, Scenario = d.Scenario, Source = d.Source,
                CreatedAt = d.CreatedAt, ExpiresAt = d.ExpiresAt, Events = d.Events,
            }).ToList();
    }

    public List<GuardAlertDto> GetAlerts(int max = 100)
    {
        lock (_lock)
            return _decisions.Alerts.AsEnumerable().Reverse().Take(max).Select(a => new GuardAlertDto
            {
                Id = a.Id, Time = a.Time, Value = a.Value, Scenario = a.Scenario, Message = a.Message, Events = a.Events, Banned = a.Banned,
            }).ToList();
    }

    public List<string> GetAllowlist()
    {
        lock (_lock) return _config.Allowlist.ToList();
    }

    // ───────────────────────── persistence ─────────────────────────

    private void SaveConfigLocked() => Persist(() => JsonStore.Save(_paths.ConfigFile, _config), "config");
    private void SaveDecisionsLocked() => Persist(() => JsonStore.Save(_paths.DecisionsFile, _decisions), "decisions");
    private void SaveFeedStatesLocked() => Persist(() => JsonStore.Save(_paths.FeedStateFile, _feedStates), "feed state");

    private void Persist(Action save, string what)
    {
        try { save(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { _log.LogError(ex, "Couldn't save Guard {What}", what); }
    }

    private static string Minutes(TimeSpan t) => t.TotalMinutes >= 1 ? $"{t.TotalMinutes:0.#} min" : $"{t.TotalSeconds:0} s";
    private static string Trim(string s, int max) => s.Trim().Length <= max ? s.Trim() : s.Trim()[..max];

    public void Dispose()
    {
        _syncGate.Dispose();
        _feedGate.Dispose();
        _signal.Dispose();
    }
}
