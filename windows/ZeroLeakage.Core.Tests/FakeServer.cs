using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ZeroLeakage.Shared.Link;

namespace ZeroLeakage.Core.Tests;

/// <summary>A tiny in-process ZeroLeakage Server: pairing codes, username/password sign-in, per-user rules and extras, admin locks.</summary>
public sealed class FakeServer : HttpMessageHandler
{
    public sealed class UserData
    {
        public Dictionary<string, SyncRule> Rules { get; } = new();
        public UserPolicy Extras { get; set; } = new();
    }

    public readonly Dictionary<string, string> Codes = new() { ["ZL-ABCD-2345"] = "alice" };
    public readonly Dictionary<string, string> Passwords = new() { ["alice"] = "correct horse", ["bob"] = "hunter2" };
    public readonly Dictionary<string, string> Tokens = new();      // token -> user
    public readonly Dictionary<string, UserData> Users = new();
    public LockedPolicy Locked { get; set; } = new() { Lists = new() { "adguard_dns" }, Services = new() { "tiktok" }, Categories = new(), BlockDomains = new() { "casino.example" } };
    public List<CustomListDto> AdminCustomLists { get; set; } = new();
    public Dictionary<string, string[]> ServiceDomains { get; } = new() { ["tiktok"] = new[] { "tiktok.com", "tiktokv.com" }, ["youtube"] = new[] { "youtube.com" } };
    public GuardPolicyDto Guard { get; set; } = new() { Enabled = true, DropMaliciousIps = true };
    public bool BypassBlocking { get; set; }
    public int PolicyVersion { get; set; } = 7;
    public readonly List<(string Method, string Path, string? Auth, string Body)> Requests = new();
    public SyncPush? LastPush { get; private set; }

    public UserData User(string name) => Users.TryGetValue(name, out var u) ? u : Users[name] = new UserData();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        var path = request.RequestUri!.AbsolutePath;
        var auth = request.Headers.Authorization?.Parameter;
        Requests.Add((request.Method.Method, path, auth, body));
        using var doc = body.Length > 0 ? JsonDocument.Parse(body) : null;

        if (request.Method == HttpMethod.Post && path == "/api/v1/devices/pair")
        {
            var code = doc!.RootElement.GetProperty("code").GetString()!;
            if (doc.RootElement.GetProperty("platform").GetString() != "windows") return new HttpResponseMessage(HttpStatusCode.BadRequest);
            return Codes.Remove(code, out var user) ? Linked(user, doc) : Status(HttpStatusCode.Unauthorized, "invalid code");
        }
        if (request.Method == HttpMethod.Post && path == "/api/v1/devices/link")
        {
            var user = doc!.RootElement.GetProperty("username").GetString()!;
            var pw = doc.RootElement.GetProperty("password").GetString();
            return Passwords.TryGetValue(user, out var expected) && expected == pw ? Linked(user, doc) : Status(HttpStatusCode.Unauthorized, "bad credentials");
        }
        if (path == "/api/v1/sync")
        {
            if (auth is null || !Tokens.TryGetValue(auth, out var user)) return Status(HttpStatusCode.Unauthorized, "unknown token");
            var data = User(user);
            if (request.Method == HttpMethod.Put)
            {
                var push = JsonSerializer.Deserialize<SyncPush>(body, ServerApiClient.Json)!;
                LastPush = push;
                foreach (var r in push.Rules)
                {
                    var key = r.Kind + "|" + r.Domain;
                    if (!data.Rules.TryGetValue(key, out var cur) || r.UpdatedAt >= cur.UpdatedAt) data.Rules[key] = r;   // last writer wins
                }
                if (push.UserPolicy is not null) data.Extras = push.UserPolicy;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(new { ok = true }) };
            }
            return Json(BuildSync(user, data));
        }
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private SyncResponse BuildSync(string user, UserData data)
    {
        var services = (Locked.Services ?? new()).Union(data.Extras.Services).ToList();
        var effectiveBlock = services.SelectMany(s => ServiceDomains.TryGetValue(s, out var d) ? d : Array.Empty<string>()).ToList();
        return new SyncResponse
        {
            Rules = data.Rules.Values.ToList(),
            ServerTime = "1790000000000",
            DeviceId = "dev-" + user,
            DohUrl = "https://zl.example.net/dns-query/dev-" + user,
            DotHost = "dev-" + user + ".zl.example.net",
            PolicyVersion = PolicyVersion.ToString(),
            Policy = new SyncPolicy
            {
                Lists = (Locked.Lists ?? new()).Union(data.Extras.Lists).ToList(),
                CustomLists = AdminCustomLists.Concat(data.Extras.CustomLists).ToList(),
                Services = services,
                Categories = (Locked.Categories ?? new()).Union(data.Extras.Categories).ToList(),
                Guard = Guard,
                BypassBlocking = BypassBlocking,
            },
            Effective = new EffectiveRules { Allow = new(), Block = effectiveBlock },
            Locked = Locked,
            UserPolicy = data.Extras.Clone(),
            User = new ServerUser { Username = user },
        };
    }

    private HttpResponseMessage Linked(string user, JsonDocument doc)
    {
        var token = "tok-" + Guid.NewGuid().ToString("N");
        Tokens[token] = user;
        User(user);
        return Json(new LinkResponse
        {
            Token = token,
            Device = new LinkedDevice { Id = "dev-" + user, Name = doc.RootElement.GetProperty("deviceName").GetString(), DohUrl = "https://zl.example.net/dns-query/dev-" + user },
            Server = new ServerInfo { Name = "Home server", Version = "2.0.0", Hostname = "zl.example.net" },
        });
    }

    private static HttpResponseMessage Json<T>(T value) =>
        new(HttpStatusCode.OK) { Content = JsonContent.Create(value, options: ServerApiClient.Json) };

    private static HttpResponseMessage Status(HttpStatusCode code, string error) =>
        new(code) { Content = JsonContent.Create(new { error }) };
}

/// <summary>The desktop app's filter state, in memory (what FilterListService does in the real app).</summary>
public sealed class FakeTarget : ISyncTarget
{
    public static readonly string[] Catalog = { "win_telemetry", "analytics_sdk", "adguard_dns", "oisd_small", "hagezi_pro", "easyprivacy" };
    public HashSet<string> Enabled { get; } = new(StringComparer.OrdinalIgnoreCase) { "win_telemetry", "analytics_sdk", "oisd_small" };
    public List<CustomListSpec> Custom { get; } = new() { new CustomListSpec { Url = "https://mine.example/list.txt", Name = "Mine" } };
    public List<string> Allow { get; } = new() { "my-bank.example" };
    public List<string> Block { get; } = new() { "my-annoying.example" };
    public List<string> ManagedBlock { get; private set; } = new();
    public List<string> ManagedAllow { get; private set; } = new();
    public HashSet<string> Locked { get; private set; } = new();
    public bool Bypass { get; private set; }
    public string? ManagedBy { get; private set; }
    public SyncPlan? LastPlan { get; private set; }

    public IReadOnlyCollection<string> CatalogListIds => Catalog;

    public Task<LocalProtectionSnapshot> SnapshotAsync() => Task.FromResult(new LocalProtectionSnapshot
    {
        EnabledLists = Enabled.ToList(),
        CustomLists = Custom.Select(c => new CustomListSpec { Url = c.Url, Name = c.Name, Category = c.Category, Enabled = c.Enabled, Locked = c.Locked }).ToList(),
        Allow = Allow.ToList(),
        Block = Block.ToList(),
    });

    public Task ApplyAsync(SyncPlan plan, CancellationToken ct)
    {
        LastPlan = plan;
        Enabled.Clear();
        Enabled.UnionWith(plan.EnabledLists);
        Custom.Clear();
        Custom.AddRange(plan.CustomLists);
        Allow.Clear(); Allow.AddRange(plan.Allow);
        Block.Clear(); Block.AddRange(plan.Block);
        ManagedBlock = plan.ManagedBlock;
        ManagedAllow = plan.ManagedAllow;
        Locked = plan.LockedLists;
        Bypass = plan.BypassBlocking;
        ManagedBy = plan.ManagedBy;
        return Task.CompletedTask;
    }

    public Task RestoreAsync(LocalProtectionSnapshot s, CancellationToken ct)
    {
        Enabled.Clear(); Enabled.UnionWith(s.EnabledLists);
        Custom.Clear(); Custom.AddRange(s.CustomLists);
        Allow.Clear(); Allow.AddRange(s.Allow);
        Block.Clear(); Block.AddRange(s.Block);
        ManagedBlock = new(); ManagedAllow = new(); Locked = new(); Bypass = false; ManagedBy = null;
        return Task.CompletedTask;
    }

    /// <summary>What the app's DNS page does when the user tries to allow a domain.</summary>
    public string? TryUserAllow(PolicyLocks locks, string domain)
    {
        if (!locks.CanAllow(domain, out var reason)) return reason;
        Block.Remove(domain);
        if (!Allow.Contains(domain)) Allow.Add(domain);
        return null;
    }
}

public sealed class FakeCore : ICoreBridge
{
    public readonly List<string> Calls = new();
    public CoreLinkInfo? Link;
    public bool Running = true;

    public Task<bool> SetLinkAsync(CoreLinkInfo info, CancellationToken ct) { Calls.Add("link"); Link = info; return Task.FromResult(Running); }
    public Task<bool> ClearLinkAsync(CancellationToken ct) { Calls.Add("clear"); Link = null; return Task.FromResult(Running); }
    public Task<bool> SetGuardPolicyAsync(bool enabled, bool drop, CancellationToken ct) { Calls.Add($"guard {enabled} {drop}"); return Task.FromResult(Running); }
    public Task<(bool Ok, string? Error)> SetDnsModeAsync(bool enabled, CancellationToken ct) { Calls.Add($"dns {enabled}"); return Task.FromResult((Running, Running ? null : "not running")); }
}

public sealed class MemoryLinkStore : ILinkStore
{
    public string? Json;
    public LinkState? Load() => Json is null ? null : JsonSerializer.Deserialize<LinkState>(Json, ServerApiClient.Json);
    public void Save(LinkState state) => Json = JsonSerializer.Serialize(state, ServerApiClient.Json);
    public void Delete() => Json = null;
}
