using System.Security.Cryptography;
using System.Text.Json;

namespace ZeroLeakage.Shared.Link;

/// <summary>Everything about the link to a ZeroLeakage Server. Persisted DPAPI-encrypted (CurrentUser) — it holds the device token.</summary>
public sealed class LinkState
{
    public string ServerUrl { get; set; } = "";
    public string Token { get; set; } = "";
    public string? DeviceId { get; set; }
    public string DeviceName { get; set; } = "";
    public string? Username { get; set; }
    public string ServerName { get; set; } = "";
    public string? ServerVersion { get; set; }
    public string? ServerHostname { get; set; }
    public string? DohUrl { get; set; }
    public string? DotHost { get; set; }
    public DateTimeOffset LinkedAt { get; set; }
    public DateTimeOffset? LastSync { get; set; }
    public string? PolicyVersion { get; set; }
    public string? LastError { get; set; }
    public bool Revoked { get; set; }
    /// <summary>False until the first pull after linking: the server's state replaces the local one, nothing is uploaded.</summary>
    public bool InitialSyncDone { get; set; }
    public bool UseServerDns { get; set; }

    /// <summary>The user's rules as last confirmed by the server.</summary>
    public List<SyncRule> KnownRules { get; set; } = new();
    /// <summary>Local rule edits not yet acknowledged by the server.</summary>
    public List<SyncRule> PendingRules { get; set; } = new();
    public UserPolicy? UserPolicy { get; set; }
    /// <summary>Local edits to the user's extras, not yet pushed.</summary>
    public UserPolicy? PendingUserPolicy { get; set; }
    public SyncPolicy? Policy { get; set; }
    public LockedPolicy? Locked { get; set; }
    /// <summary>The PC's own protection from before linking; restored by Unlink.</summary>
    public LocalProtectionSnapshot? PreLinkBackup { get; set; }
}

public interface ILinkStore
{
    LinkState? Load();
    void Save(LinkState state);
    void Delete();
}

/// <summary>%LocalAppData%\ZeroLeakage\link.dat, encrypted with DPAPI for the current Windows user only.</summary>
public sealed class DpapiLinkStore : ILinkStore
{
    private static readonly byte[] Entropy = "ZeroLeakage.Link.v1"u8.ToArray();
    private readonly string _path;

    public DpapiLinkStore(string path) => _path = path;

    public static string DefaultPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ZeroLeakage", "link.dat");

    public LinkState? Load()
    {
        try
        {
            if (!File.Exists(_path)) return null;
            var plain = ProtectedData.Unprotect(File.ReadAllBytes(_path), Entropy, DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<LinkState>(plain, ServerApiClient.Json);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or IOException or UnauthorizedAccessException)
        {
            return null;   // another user's file, or damaged: treat as not linked
        }
    }

    public void Save(LinkState state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var plain = JsonSerializer.SerializeToUtf8Bytes(state, ServerApiClient.Json);
        var cipher = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
        CryptographicOperations.ZeroMemory(plain);
        var tmp = _path + ".tmp";
        File.WriteAllBytes(tmp, cipher);
        File.Move(tmp, _path, overwrite: true);
    }

    public void Delete()
    {
        try { File.Delete(_path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

public sealed class CustomListSpec
{
    public string Url { get; set; } = "";
    public string Name { get; set; } = "";
    public string Category { get; set; } = "Custom List";
    public bool Enabled { get; set; } = true;
    /// <summary>Set by the server admin: can't be removed from the app.</summary>
    public bool Locked { get; set; }
}

/// <summary>The PC's filter protection: enabled catalog lists, custom lists and the user's allow/block rules.</summary>
public sealed class LocalProtectionSnapshot
{
    public List<string> EnabledLists { get; set; } = new();
    public List<CustomListSpec> CustomLists { get; set; } = new();
    public List<string> Allow { get; set; } = new();
    public List<string> Block { get; set; } = new();
}

/// <summary>What the app should look like after a sync: an exact clone of the server's protection for this user.</summary>
public sealed class SyncPlan
{
    public string ManagedBy { get; set; } = "";
    public HashSet<string> EnabledLists { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> LockedLists { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<CustomListSpec> CustomLists { get; set; } = new();
    public List<string> Allow { get; set; } = new();
    public List<string> Block { get; set; } = new();
    /// <summary>The user's allow rules that the admin's baseline overrides (kept on the server, not applied).</summary>
    public List<string> RejectedAllows { get; set; } = new();
    /// <summary>Server-computed allow/block domains (services, categories…) that aren't the user's own rules.</summary>
    public List<string> ManagedAllow { get; set; } = new();
    public List<string> ManagedBlock { get; set; } = new();
    public List<string> LockedBlockDomains { get; set; } = new();
    public bool BypassBlocking { get; set; }
    /// <summary>Server list ids this app has no equivalent for.</summary>
    public List<string> UnknownLists { get; set; } = new();
    public PolicyLocks Locks { get; set; } = PolicyLocks.None;
}

/// <summary>The admin's baseline as the app enforces it: what can't be switched off or unblocked locally.</summary>
public sealed class PolicyLocks
{
    public static readonly PolicyLocks None = new(Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(), "");

    private readonly HashSet<string> _lists, _services, _categories, _blockDomains;

    public PolicyLocks(IEnumerable<string> lists, IEnumerable<string> services, IEnumerable<string> categories,
        IEnumerable<string> blockDomains, string managedBy)
    {
        _lists = new HashSet<string>(lists, StringComparer.OrdinalIgnoreCase);
        _services = new HashSet<string>(services, StringComparer.OrdinalIgnoreCase);
        _categories = new HashSet<string>(categories, StringComparer.OrdinalIgnoreCase);
        _blockDomains = new HashSet<string>(blockDomains.Select(DomainName.Normalize).OfType<string>(), StringComparer.Ordinal);
        ManagedBy = managedBy;
    }

    public string ManagedBy { get; }
    public IReadOnlyCollection<string> Lists => _lists;
    public IReadOnlyCollection<string> Services => _services;
    public IReadOnlyCollection<string> Categories => _categories;
    public IReadOnlyCollection<string> BlockDomains => _blockDomains;
    public bool IsEmpty => _lists.Count == 0 && _services.Count == 0 && _categories.Count == 0 && _blockDomains.Count == 0;

    public bool IsListLocked(string id) => _lists.Contains(id);
    public bool IsServiceLocked(string id) => _services.Contains(id);
    public bool IsCategoryLocked(string id) => _categories.Contains(id);

    /// <summary>True when the admin blocks this domain (or a parent domain) for the whole network.</summary>
    public bool BlocksDomain(string domain, out string? lockedEntry)
    {
        lockedEntry = null;
        var d = DomainName.Normalize(domain);
        if (d is null || _blockDomains.Count == 0) return false;
        for (var s = d; ; )
        {
            if (_blockDomains.Contains(s)) { lockedEntry = s; return true; }
            int dot = s.IndexOf('.');
            if (dot < 0) return false;
            s = s[(dot + 1)..];
        }
    }

    /// <summary>Users may add stricter rules, but never unblock something in the admin's baseline.</summary>
    public bool CanAllow(string domain, out string? reason)
    {
        reason = null;
        if (!BlocksDomain(domain, out var entry)) return true;
        reason = $"Set by admin: {entry} is blocked for your whole network{(ManagedBy.Length > 0 ? $" ({ManagedBy})" : "")}. It can't be unblocked from this app.";
        return false;
    }
}

/// <summary>The app-side protection that sync reads from and writes to (the desktop app's filter lists and rules).</summary>
public interface ISyncTarget
{
    IReadOnlyCollection<string> CatalogListIds { get; }
    Task<LocalProtectionSnapshot> SnapshotAsync();
    Task ApplyAsync(SyncPlan plan, CancellationToken ct);
    /// <summary>Unlink: drop server management and put the pre-link protection back.</summary>
    Task RestoreAsync(LocalProtectionSnapshot snapshot, CancellationToken ct);
}

public sealed record CoreLinkInfo(Uri Server, string Token, string ServerName, string? DeviceId, string? DohUrl);

/// <summary>Talks to the ZeroLeakage Core service (Guard bouncer source, Guard policy, server DNS).</summary>
public interface ICoreBridge
{
    Task<bool> SetLinkAsync(CoreLinkInfo info, CancellationToken ct);
    Task<bool> ClearLinkAsync(CancellationToken ct);
    Task<bool> SetGuardPolicyAsync(bool enabled, bool dropMaliciousIps, CancellationToken ct);
    Task<(bool Ok, string? Error)> SetDnsModeAsync(bool enabled, CancellationToken ct);
}
