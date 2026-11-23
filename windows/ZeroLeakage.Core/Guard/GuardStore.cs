using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroLeakage.Core.Guard;

public sealed class ScenarioConfig
{
    public bool Enabled { get; set; } = true;
    public int Threshold { get; set; }
    public double WindowMinutes { get; set; }
    public double BanHours { get; set; }
}

/// <summary>Guard settings, %ProgramData%\ZeroLeakage\guard\config.json.</summary>
public sealed class GuardConfig
{
    public bool Enabled { get; set; } = true;
    public Dictionary<string, bool> Feeds { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public ScenarioConfig BruteForce { get; set; } = new() { Threshold = 5, WindowMinutes = 10, BanHours = 4 };
    public ScenarioConfig PortScan { get; set; } = new() { Threshold = 15, WindowMinutes = 1, BanHours = 24 };
    public double FeedRefreshHours { get; set; } = 24;
    public List<string> Allowlist { get; set; } = new();
    public ServerConfig Server { get; set; } = new();
    public bool ServerFeedEnabled { get; set; } = true;
    /// <summary>The linked server's Guard policy is in charge of Enabled / ServerFeedEnabled.</summary>
    public bool PolicyManaged { get; set; }
}

public sealed class ServerConfig
{
    public string? Url { get; set; }
    /// <summary>Bouncer key or device token, DPAPI LocalMachine-protected (base64).</summary>
    public string? ProtectedKey { get; set; }
    /// <summary>"manual" (bouncer key typed on the Guard page) or "link" (Account &amp; sync device token).</summary>
    public string? Source { get; set; }
    public string? ServerName { get; set; }
    public string? DeviceId { get; set; }
    public string? DohUrl { get; set; }

    [JsonIgnore] public bool IsConfigured => !string.IsNullOrEmpty(Url) && !string.IsNullOrEmpty(ProtectedKey);
    [JsonIgnore] public bool IsLinked => IsConfigured && Source == "link";
}

public sealed class Decision
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
    /// <summary>Canonical IP or CIDR.</summary>
    public string Value { get; set; } = "";
    public string Type { get; set; } = "ban";
    public string Reason { get; set; } = "";
    public string Scenario { get; set; } = "";
    public string Source { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public int Events { get; set; }
}

public sealed class AlertRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public DateTimeOffset Time { get; set; }
    public string Value { get; set; } = "";
    public string Scenario { get; set; } = "";
    public string Message { get; set; } = "";
    public int Events { get; set; }
    public bool Banned { get; set; }
}

public sealed class DecisionFile
{
    public List<Decision> Bans { get; set; } = new();
    public List<AlertRecord> Alerts { get; set; } = new();
}

public sealed class FeedState
{
    public DateTimeOffset? LastSuccess { get; set; }
    public DateTimeOffset? LastAttempt { get; set; }
    public string? ETag { get; set; }
    public string? LastModified { get; set; }
    public int Entries { get; set; }
    public int Skipped { get; set; }
    public int Invalid { get; set; }
    public string? LastError { get; set; }
}

/// <summary>Where Guard keeps its state. Production: %ProgramData%\ZeroLeakage\guard (SYSTEM + Administrators only).</summary>
public sealed class GuardPaths
{
    public GuardPaths(string root, bool hardenAcl = false)
    {
        Root = root;
        HardenAcl = hardenAcl;
    }

    public static GuardPaths Default => new(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ZeroLeakage", "guard"), hardenAcl: true);

    public string Root { get; }
    public bool HardenAcl { get; }
    public string FeedsDir => Path.Combine(Root, "feeds");
    public string ConfigFile => Path.Combine(Root, "config.json");
    public string DecisionsFile => Path.Combine(Root, "decisions.json");
    public string FeedStateFile => Path.Combine(FeedsDir, "state.json");
    public string DnsBackupFile => Path.Combine(Root, "dns-backup.json");
    public string FeedCache(string id) => Path.Combine(FeedsDir, id + ".txt");

    public void EnsureCreated()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(FeedsDir);
        if (HardenAcl) Harden(Root);
    }

    /// <summary>Protected DACL: SYSTEM and Administrators full control, nobody else (keys live here).</summary>
    public static void Harden(string dir)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(dir).SetAccessControl(sec);
    }
}

public static class JsonStore
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static T? Load<T>(string path) where T : class
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), Options) : null; }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Write-then-rename so a crash never leaves half a file.</summary>
    public static void Save<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(value, Options));
        File.Move(tmp, path, overwrite: true);
    }
}

/// <summary>DPAPI with LocalMachine scope: only code on this PC can decrypt, and the file sits in a SYSTEM/Admins-only folder.</summary>
public static class SecretProtector
{
    private static readonly byte[] Entropy = "ZeroLeakage.Core.Secret.v1"u8.ToArray();

    public static string Protect(string secret)
    {
        var plain = Encoding.UTF8.GetBytes(secret);
        try { return Convert.ToBase64String(ProtectedData.Protect(plain, Entropy, DataProtectionScope.LocalMachine)); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    public static string? Unprotect(string? protectedValue)
    {
        if (string.IsNullOrEmpty(protectedValue)) return null;
        try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(protectedValue), Entropy, DataProtectionScope.LocalMachine)); }
        catch (Exception ex) when (ex is CryptographicException or FormatException) { return null; }
    }
}
