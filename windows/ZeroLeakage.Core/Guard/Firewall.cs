using System.Security.Cryptography;
using System.Text;

namespace ZeroLeakage.Core.Guard;

public enum FwDirection { In = 1, Out = 2 }

public sealed record FwRuleSpec(string Name, FwDirection Direction, string RemoteAddresses, string Description);

public sealed record FwRuleInfo(string Name, FwDirection Direction, string Description);

/// <summary>The slice of Windows Firewall that Guard needs. Real: <see cref="WindowsFirewall"/>; tests use a fake.</summary>
public interface IFirewall
{
    /// <summary>Every rule whose Grouping equals <paramref name="group"/>.</summary>
    IReadOnlyList<FwRuleInfo> GetRules(string group);
    /// <summary>Adds a block rule (any protocol, all profiles) with the given remote addresses.</summary>
    void AddBlockRule(FwRuleSpec rule, string group);
    void RemoveRule(string name);
    /// <summary>True when the firewall is on for every currently active profile; null if unknown.</summary>
    bool? IsEnabledForCurrentProfiles();
}

/// <summary>One chunk of up to 1000 addresses, enforced by an inbound and an outbound rule.</summary>
public sealed record RuleChunk(string Kind, string Addresses, int EntryCount, string Hash);

public sealed record SyncResult(int Added, int Removed, int Kept, int Failed);

/// <summary>
/// Owns the "ZeroLeakage Guard" rule group. Rule names carry a hash of their addresses, so an update is a diff:
/// unchanged chunks stay, new chunks are added first, and only then are stale rules removed — the group is
/// replaced without ever leaving a gap in protection. If an add fails, the new rules are rolled back and the
/// previous set keeps protecting.
/// </summary>
public sealed class GuardFirewallSync
{
    public const string Group = "ZeroLeakage Guard";
    public const string NamePrefix = "ZeroLeakage Guard - ";
    public const int MaxEntriesPerRule = 1000;

    private readonly IFirewall _firewall;

    public GuardFirewallSync(IFirewall firewall) => _firewall = firewall;

    public static IReadOnlyList<RuleChunk> BuildChunks(string kind, IpRangeSet set, int maxEntries = MaxEntriesPerRule)
    {
        if (maxEntries is < 1 or > MaxEntriesPerRule) throw new ArgumentOutOfRangeException(nameof(maxEntries));
        return set.ToEntries().Chunk(maxEntries).Select(c =>
        {
            var addresses = string.Join(",", c);
            return new RuleChunk(kind, addresses, c.Length, Hash(kind + "\n" + addresses));
        }).ToList();
    }

    public static IReadOnlyList<FwRuleSpec> ToRules(IEnumerable<RuleChunk> chunks) => chunks.SelectMany(c => new[]
    {
        Rule(c, FwDirection.In),
        Rule(c, FwDirection.Out),
    }).ToList();

    private static FwRuleSpec Rule(RuleChunk c, FwDirection dir) => new(
        $"{NamePrefix}{c.Kind} {(dir == FwDirection.In ? "In" : "Out")} {c.Hash}",
        dir,
        c.Addresses,
        $"ZeroLeakage Guard: blocks {c.EntryCount} {(c.Kind == "Bans" ? "banned" : "threat-feed")} address entries ({(dir == FwDirection.In ? "inbound" : "outbound")}). Managed automatically; removed when ZeroLeakage is uninstalled.");

    public SyncResult Apply(IReadOnlyList<RuleChunk> desiredChunks)
    {
        var desired = ToRules(desiredChunks);
        var existing = _firewall.GetRules(Group);
        var existingNames = new HashSet<string>(existing.Select(r => r.Name), StringComparer.Ordinal);
        var desiredNames = new HashSet<string>(desired.Select(r => r.Name), StringComparer.Ordinal);

        // 1) add what's new
        var added = new List<string>();
        try
        {
            foreach (var rule in desired)
            {
                if (existingNames.Contains(rule.Name)) continue;
                _firewall.AddBlockRule(rule, Group);
                added.Add(rule.Name);
            }
        }
        catch
        {
            foreach (var name in added)
            {
                try { _firewall.RemoveRule(name); } catch { /* best effort rollback */ }
            }
            throw;
        }

        // 2) only then remove what's stale
        int removed = 0, failed = 0;
        foreach (var name in existing.Select(r => r.Name).Distinct(StringComparer.Ordinal))
        {
            if (desiredNames.Contains(name)) continue;
            try { _firewall.RemoveRule(name); removed++; }
            catch { failed++; }
        }
        return new SyncResult(added.Count, removed, desired.Count - added.Count, failed);
    }

    /// <summary>Removes every rule in the Guard group (service --cleanup, Guard switched off).</summary>
    public int Cleanup()
    {
        int removed = 0;
        foreach (var name in _firewall.GetRules(Group).Select(r => r.Name).Distinct(StringComparer.Ordinal))
        {
            try { _firewall.RemoveRule(name); removed++; }
            catch { /* keep going */ }
        }
        return removed;
    }

    private static string Hash(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)))[..16].ToLowerInvariant();
}
