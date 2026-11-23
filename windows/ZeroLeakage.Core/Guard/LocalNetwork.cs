using System.Net;
using System.Net.NetworkInformation;

namespace ZeroLeakage.Core.Guard;

/// <summary>Addresses Guard must never ban: this PC's own IPs, its gateways and DNS servers.</summary>
public interface ILocalNetworkInfo
{
    IReadOnlyList<IPAddress> GetProtectedAddresses();
    event EventHandler? Changed;
}

public sealed class LocalNetworkInfo : ILocalNetworkInfo, IDisposable
{
    private readonly object _lock = new();
    private IReadOnlyList<IPAddress>? _cache;

    public LocalNetworkInfo()
    {
        NetworkChange.NetworkAddressChanged += OnChanged;
    }

    public event EventHandler? Changed;

    public IReadOnlyList<IPAddress> GetProtectedAddresses()
    {
        lock (_lock) return _cache ??= Collect();
    }

    private static IReadOnlyList<IPAddress> Collect()
    {
        var set = new HashSet<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                IPInterfaceProperties props;
                try { props = nic.GetIPProperties(); }
                catch (NetworkInformationException) { continue; }
                foreach (var u in props.UnicastAddresses) set.Add(Normalize(u.Address));
                foreach (var g in props.GatewayAddresses) set.Add(Normalize(g.Address));
                foreach (var d in props.DnsAddresses) set.Add(Normalize(d));
                try { foreach (var d in props.DhcpServerAddresses) set.Add(Normalize(d)); }
                catch (PlatformNotSupportedException) { }
            }
        }
        catch (NetworkInformationException) { }
        set.RemoveWhere(a => a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any));
        return set.ToList();
    }

    private static IPAddress Normalize(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (a.ScopeId != 0) a = new IPAddress(a.GetAddressBytes());
        return a;
    }

    private void OnChanged(object? sender, EventArgs e)
    {
        lock (_lock) _cache = null;
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Dispose() => NetworkChange.NetworkAddressChanged -= OnChanged;
}
