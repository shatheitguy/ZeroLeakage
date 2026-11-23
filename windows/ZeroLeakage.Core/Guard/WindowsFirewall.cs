using System.Collections;
using System.Runtime.InteropServices;

namespace ZeroLeakage.Core.Guard;

/// <summary>Windows Defender Firewall through the INetFwPolicy2 COM API (HNetCfg.FwPolicy2). Writes need SYSTEM/admin.</summary>
public sealed class WindowsFirewall : IFirewall
{
    private const int ProtocolAny = 256;
    private const int ActionBlock = 0;
    private const int ProfilesAll = 0x7FFFFFFF;
    private readonly object _lock = new();

    private static dynamic CreatePolicy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;

    public IReadOnlyList<FwRuleInfo> GetRules(string group)
    {
        lock (_lock)
        {
            dynamic policy = CreatePolicy();
            var result = new List<FwRuleInfo>();
            try
            {
                foreach (dynamic rule in (IEnumerable)policy.Rules)
                {
                    try
                    {
                        string? grouping = rule.Grouping;
                        if (!string.Equals(grouping, group, StringComparison.Ordinal)) continue;
                        result.Add(new FwRuleInfo((string)rule.Name, (FwDirection)(int)rule.Direction, (string?)rule.Description ?? ""));
                    }
                    finally { Release(rule); }
                }
            }
            finally { Release(policy); }
            return result;
        }
    }

    /// <summary>Total number of firewall rules (read-only diagnostics).</summary>
    public int CountAllRules()
    {
        lock (_lock)
        {
            dynamic policy = CreatePolicy();
            try { return (int)policy.Rules.Count; }
            finally { Release(policy); }
        }
    }

    public void AddBlockRule(FwRuleSpec spec, string group)
    {
        lock (_lock)
        {
            dynamic policy = CreatePolicy();
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!)!;
            try
            {
                rule.Name = spec.Name;
                rule.Description = spec.Description;
                rule.Grouping = group;
                rule.Protocol = ProtocolAny;
                rule.Direction = (int)spec.Direction;
                rule.Action = ActionBlock;
                rule.RemoteAddresses = spec.RemoteAddresses;
                rule.Profiles = ProfilesAll;
                rule.InterfaceTypes = "All";
                rule.Enabled = true;
                policy.Rules.Add(rule);
            }
            finally
            {
                Release(rule);
                Release(policy);
            }
        }
    }

    public void RemoveRule(string name)
    {
        // Only ever called with Guard's own names ("ZeroLeakage Guard - …"); Remove() matches by name.
        if (!name.StartsWith(GuardFirewallSync.NamePrefix, StringComparison.Ordinal))
            throw new InvalidOperationException("Refusing to remove a rule Guard doesn't own");
        lock (_lock)
        {
            dynamic policy = CreatePolicy();
            try { policy.Rules.Remove(name); }
            finally { Release(policy); }
        }
    }

    public bool? IsEnabledForCurrentProfiles()
    {
        try
        {
            lock (_lock)
            {
                dynamic policy = CreatePolicy();
                try
                {
                    int current = policy.CurrentProfileTypes;
                    foreach (var profile in new[] { 1, 2, 4 })
                    {
                        if ((current & profile) == 0) continue;
                        bool on = policy.FirewallEnabled[profile];
                        if (!on) return false;
                    }
                    return true;
                }
                finally { Release(policy); }
            }
        }
        catch (Exception ex) when (ex is COMException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
        {
            return null;
        }
    }

    private static void Release(object? com)
    {
        if (com is not null && Marshal.IsComObject(com)) Marshal.ReleaseComObject(com);
    }
}
