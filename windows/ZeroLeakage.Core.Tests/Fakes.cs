using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using ZeroLeakage.Core.Dns;
using ZeroLeakage.Core.Guard;

namespace ZeroLeakage.Core.Tests;

public sealed class ManualClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>In-memory Windows Firewall that records the order of operations.</summary>
public sealed class FakeFirewall : IFirewall
{
    public readonly Dictionary<string, (FwRuleSpec Spec, string Group)> Rules = new();
    public readonly List<string> Log = new();
    public Func<FwRuleSpec, bool>? FailAdd;

    public IReadOnlyList<FwRuleInfo> GetRules(string group) =>
        Rules.Values.Where(r => r.Group == group).Select(r => new FwRuleInfo(r.Spec.Name, r.Spec.Direction, r.Spec.Description)).ToList();

    public void AddBlockRule(FwRuleSpec rule, string group)
    {
        if (FailAdd?.Invoke(rule) == true) throw new InvalidOperationException("simulated COM failure");
        if (rule.RemoteAddresses.Split(',').Length > GuardFirewallSync.MaxEntriesPerRule) throw new InvalidOperationException("too many addresses");
        Rules[rule.Name] = (rule, group);
        Log.Add("add " + rule.Name);
    }

    public void RemoveRule(string name)
    {
        Rules.Remove(name);
        Log.Add("remove " + name);
    }

    public bool? IsEnabledForCurrentProfiles() => true;

    public IEnumerable<string> AllAddresses(string group = GuardFirewallSync.Group) =>
        Rules.Values.Where(r => r.Group == group).SelectMany(r => r.Spec.RemoteAddresses.Split(','));

    public bool Blocks(string ip, FwDirection dir = FwDirection.In)
    {
        var addr = IPAddress.Parse(ip);
        var set = IpRangeSet.Parse(Rules.Values.Where(r => r.Spec.Direction == dir).SelectMany(r => r.Spec.RemoteAddresses.Split(',')));
        return set.Contains(addr);
    }
}

public sealed class FakeFeedSource : IFeedSource
{
    public readonly Dictionary<string, string> Texts = new(StringComparer.OrdinalIgnoreCase);
    // Background feed refreshes call in from other threads.
    public readonly System.Collections.Concurrent.ConcurrentQueue<(string Id, string? Token)> Calls = new();

    public Task<FeedFetchResult> FetchAsync(FeedDefinition feed, string? etag, string? lastModified, CancellationToken ct)
    {
        Calls.Enqueue((feed.Id, feed.BearerToken));
        return Task.FromResult(Texts.TryGetValue(feed.Id, out var t)
            ? new FeedFetchResult(FetchStatus.Updated, t, "\"etag\"")
            : new FeedFetchResult(FetchStatus.Failed, Error: "HTTP 404"));
    }
}

public sealed class FakeNetwork : ILocalNetworkInfo
{
    public List<IPAddress> Addresses { get; } = new() { IPAddress.Parse("192.168.1.20"), IPAddress.Parse("192.168.1.1") };
    public IReadOnlyList<IPAddress> GetProtectedAddresses() => Addresses;
    public event EventHandler? Changed;
    public void RaiseChanged() => Changed?.Invoke(this, EventArgs.Empty);
}

/// <summary>Pretends to be Windows' DNS client: adapters with saved name servers that can be changed and put back.</summary>
public sealed class FakeDnsConfigurator : IDnsConfigurator
{
    public readonly Dictionary<string, (string V4, string V6)> Current = new()
    {
        ["{eth}"] = ("", ""),                              // DHCP
        ["{wifi}"] = ("9.9.9.9,149.112.112.112", ""),      // static
    };
    public readonly Dictionary<string, string> DohTemplates = new();
    public readonly List<string> Log = new();
    public bool Supported = true;
    public bool FailPointing;

    public bool IsSupported(out string? reason)
    {
        reason = Supported ? null : "Windows DNS over HTTPS needs Windows 11";
        return Supported;
    }

    public IReadOnlyList<DnsAdapterState> CaptureAdapters() => Current.Select(kv => new DnsAdapterState
    {
        InterfaceId = kv.Key, Name = kv.Key.Trim('{', '}'), V4NameServers = kv.Value.V4, V6NameServers = kv.Value.V6,
    }).ToList();

    public bool RegisterDoh(string serverIp, string dohTemplate)
    {
        bool added = !DohTemplates.ContainsKey(serverIp);
        DohTemplates[serverIp] = dohTemplate;
        Log.Add($"doh {serverIp} {dohTemplate}");
        return added;
    }

    public void UnregisterDoh(string serverIp)
    {
        DohTemplates.Remove(serverIp);
        Log.Add($"undoh {serverIp}");
    }

    public void PointAdapterAt(DnsAdapterState adapter, string serverIp)
    {
        if (FailPointing) throw new InvalidOperationException("netsh failed");
        Current[adapter.InterfaceId] = (serverIp, "none");
        Log.Add($"point {adapter.Name} {serverIp}");
    }

    public void RestoreAdapter(DnsAdapterState adapter)
    {
        Current[adapter.InterfaceId] = (adapter.V4NameServers, adapter.V6NameServers);
        Log.Add($"restore {adapter.Name}");
    }

    public void FlushCache() => Log.Add("flush");
}

/// <summary>A Guard engine on a temp folder with fake firewall, feeds, network and DNS.</summary>
public sealed class TestGuard : IDisposable
{
    public readonly string Dir = Path.Combine(Path.GetTempPath(), "zl-guard-tests", Guid.NewGuid().ToString("N"));
    public readonly FakeFirewall Firewall = new();
    public readonly FakeFeedSource Feeds = new();
    public readonly FakeNetwork Network = new();
    public readonly FakeDnsConfigurator Dns = new();
    public readonly ManualClock Clock = new();
    public readonly GuardEngine Engine;
    public readonly GuardPaths Paths;

    public TestGuard(bool allFeedsOff = true)
    {
        Paths = new GuardPaths(Dir);
        if (allFeedsOff)
        {
            // Start with every built-in feed off so each test opts in explicitly.
            Directory.CreateDirectory(Dir);
            var cfg = new GuardConfig();
            foreach (var f in FeedCatalog.Builtin) cfg.Feeds[f.Id] = false;
            JsonStore.Save(Paths.ConfigFile, cfg);
        }
        Engine = new GuardEngine(Paths, Firewall, Feeds, Network, Dns, Clock, NullLogger<GuardEngine>.Instance,
            (host, _) => Task.FromResult(new[] { IPAddress.Parse("203.0.113.50") }));
        Engine.Initialize();
    }

    public void Dispose()
    {
        Engine.Dispose();
        try { Directory.Delete(Dir, true); } catch { }
    }
}
