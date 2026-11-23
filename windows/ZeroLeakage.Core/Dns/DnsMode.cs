using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using ZeroLeakage.Core.Guard;

namespace ZeroLeakage.Core.Dns;

/// <summary>An adapter's DNS settings before ZeroLeakage changed them ("" = from DHCP / router).</summary>
public sealed class DnsAdapterState
{
    public string InterfaceId { get; set; } = "";
    public string Name { get; set; } = "";
    public string V4NameServers { get; set; } = "";
    public string V6NameServers { get; set; } = "";
}

public sealed class DnsBackup
{
    public List<DnsAdapterState> Adapters { get; set; } = new();
    public string ServerIp { get; set; } = "";
    public string DohTemplate { get; set; } = "";
    /// <summary>We created the DoH entry for ServerIp (so Disable removes it again).</summary>
    public bool AddedEncryption { get; set; }
    public DateTimeOffset AppliedAt { get; set; }
}

/// <summary>Windows DNS client settings. Real: netsh (needs SYSTEM). Tests: a fake.</summary>
public interface IDnsConfigurator
{
    bool IsSupported(out string? reason);
    IReadOnlyList<DnsAdapterState> CaptureAdapters();
    /// <summary>Registers the DoH template for the server IP. True if a new entry was created.</summary>
    bool RegisterDoh(string serverIp, string dohTemplate);
    void UnregisterDoh(string serverIp);
    void PointAdapterAt(DnsAdapterState adapter, string serverIp);
    void RestoreAdapter(DnsAdapterState adapter);
    void FlushCache();
}

/// <summary>
/// "Use the server as this PC's DNS": saves every active adapter's DNS first, registers the server's DoH template
/// (netsh dns add encryption … autoupgrade=yes udpfallback=no) and points the adapters at the server.
/// Disable (toggle off or Unlink) puts the saved settings back exactly. The backup survives restarts.
/// </summary>
public sealed class DnsModeManager
{
    private readonly IDnsConfigurator _dns;
    private readonly string _backupPath;
    private readonly TimeProvider _clock;
    private readonly object _lock = new();

    public DnsModeManager(IDnsConfigurator dns, string backupPath, TimeProvider clock)
    {
        _dns = dns;
        _backupPath = backupPath;
        _clock = clock;
    }

    public DnsBackup? Backup => JsonStore.Load<DnsBackup>(_backupPath);
    public bool IsEnabled => File.Exists(_backupPath);
    public string? LastError { get; private set; }

    public bool IsSupported(out string? reason) => _dns.IsSupported(out reason);

    public (bool Ok, string? Error) Enable(string serverIp, string dohTemplate)
    {
        lock (_lock)
        {
            if (!_dns.IsSupported(out var why)) return Fail(why ?? "Not supported on this version of Windows");
            if (!Uri.TryCreate(dohTemplate, UriKind.Absolute, out var t) || t.Scheme != Uri.UriSchemeHttps)
                return Fail("The server's DNS-over-HTTPS address must be https://");
            if (!System.Net.IPAddress.TryParse(serverIp, out _)) return Fail("No IP address for the server");

            var backup = Backup;
            if (backup is not null && backup.ServerIp == serverIp && backup.DohTemplate == dohTemplate) return (true, null);
            try
            {
                if (backup is null)
                {
                    // Save first: whatever happens next, Disable can put the PC back.
                    backup = new DnsBackup { Adapters = _dns.CaptureAdapters().ToList(), AppliedAt = _clock.GetUtcNow() };
                    if (backup.Adapters.Count == 0) return Fail("No active network adapter to configure");
                }
                else if (backup.AddedEncryption && backup.ServerIp != serverIp)
                {
                    _dns.UnregisterDoh(backup.ServerIp);
                    backup.AddedEncryption = false;
                }
                backup.ServerIp = serverIp;
                backup.DohTemplate = dohTemplate;
                JsonStore.Save(_backupPath, backup);

                backup.AddedEncryption |= _dns.RegisterDoh(serverIp, dohTemplate);
                JsonStore.Save(_backupPath, backup);
                foreach (var a in backup.Adapters) _dns.PointAdapterAt(a, serverIp);
                _dns.FlushCache();
                LastError = null;
                return (true, null);
            }
            catch (Exception ex)
            {
                var restore = Disable();
                return Fail($"Couldn't switch Windows DNS: {ex.Message}{(restore.Ok ? " (previous DNS restored)" : "")}");
            }
        }
    }

    public (bool Ok, string? Error) Disable()
    {
        lock (_lock)
        {
            var backup = Backup;
            if (backup is null) return (true, null);
            var errors = new List<string>();
            foreach (var a in backup.Adapters)
            {
                try { _dns.RestoreAdapter(a); }
                catch (Exception ex) { errors.Add($"{a.Name}: {ex.Message}"); }
            }
            if (backup.AddedEncryption && backup.ServerIp.Length > 0)
            {
                try { _dns.UnregisterDoh(backup.ServerIp); }
                catch (Exception ex) { errors.Add("DoH entry: " + ex.Message); }
            }
            try { _dns.FlushCache(); } catch { /* cosmetic */ }
            if (errors.Count > 0) return Fail("Couldn't fully restore DNS: " + string.Join("; ", errors));
            try { File.Delete(_backupPath); } catch (IOException) { }
            LastError = null;
            return (true, null);
        }
    }

    private (bool, string?) Fail(string error)
    {
        LastError = error;
        return (false, error);
    }
}

/// <summary>Real implementation via netsh and the Tcpip registry keys. Only ever runs inside the service (SYSTEM).</summary>
public sealed class WindowsDnsConfigurator : IDnsConfigurator
{
    private static readonly string Netsh = Path.Combine(Environment.SystemDirectory, "netsh.exe");
    private static readonly string IpConfig = Path.Combine(Environment.SystemDirectory, "ipconfig.exe");

    public bool IsSupported(out string? reason)
    {
        // Built-in DNS over HTTPS: Windows 11 (22000) and Windows Server 2022 (20348).
        reason = Environment.OSVersion.Version.Build >= 20348 ? null : "Windows DNS over HTTPS needs Windows 11";
        return reason is null;
    }

    public IReadOnlyList<DnsAdapterState> CaptureAdapters()
    {
        var list = new List<DnsAdapterState>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            var props = nic.GetIPProperties();
            if (!props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork)) continue;
            list.Add(new DnsAdapterState
            {
                InterfaceId = nic.Id,
                Name = nic.Name,
                V4NameServers = ReadNameServer(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + nic.Id),
                V6NameServers = ReadNameServer(@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\" + nic.Id),
            });
        }
        return list;
    }

    private static string ReadNameServer(string key)
    {
        using var k = Registry.LocalMachine.OpenSubKey(key);
        return (k?.GetValue("NameServer") as string)?.Trim() ?? "";
    }

    public bool RegisterDoh(string serverIp, string dohTemplate)
    {
        if (Run(Netsh, "dns", "add", "encryption", $"server={serverIp}", $"dohtemplate={dohTemplate}", "autoupgrade=yes", "udpfallback=no") == 0)
            return true;
        if (Run(Netsh, "dns", "set", "encryption", $"server={serverIp}", $"dohtemplate={dohTemplate}", "autoupgrade=yes", "udpfallback=no") == 0)
            return false;
        throw new InvalidOperationException("netsh couldn't register the DNS-over-HTTPS template");
    }

    public void UnregisterDoh(string serverIp) => Run(Netsh, "dns", "delete", "encryption", $"server={serverIp}");

    public void PointAdapterAt(DnsAdapterState adapter, string serverIp)
    {
        bool v4 = System.Net.IPAddress.Parse(serverIp).AddressFamily == AddressFamily.InterNetwork;
        Check(Run(Netsh, "interface", v4 ? "ipv4" : "ipv6", "set", "dnsservers", $"name={adapter.Name}", "source=static",
            $"address={serverIp}", "register=none", "validate=no"), adapter.Name);
        // The other family gets no resolver at all, so queries can't slip around the server.
        Run(Netsh, "interface", v4 ? "ipv6" : "ipv4", "set", "dnsservers", $"name={adapter.Name}", "source=static",
            "address=none", "register=none", "validate=no");
    }

    public void RestoreAdapter(DnsAdapterState adapter)
    {
        Restore(adapter, "ipv4", adapter.V4NameServers);
        Restore(adapter, "ipv6", adapter.V6NameServers);
    }

    private static void Restore(DnsAdapterState adapter, string family, string saved)
    {
        var servers = saved.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries);
        if (servers.Length == 0)
        {
            Check(Run(Netsh, "interface", family, "set", "dnsservers", $"name={adapter.Name}", "source=dhcp"), adapter.Name);
            return;
        }
        Check(Run(Netsh, "interface", family, "set", "dnsservers", $"name={adapter.Name}", "source=static",
            $"address={servers[0]}", "register=primary", "validate=no"), adapter.Name);
        for (int i = 1; i < servers.Length; i++)
            Run(Netsh, "interface", family, "add", "dnsservers", $"name={adapter.Name}", $"address={servers[i]}", $"index={i + 1}", "validate=no");
    }

    public void FlushCache() => Run(IpConfig, "/flushdns");

    private static void Check(int exitCode, string adapter)
    {
        if (exitCode != 0) throw new InvalidOperationException($"netsh failed for adapter {adapter} (exit {exitCode})");
    }

    private static int Run(string exe, params string[] args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.StandardOutput.ReadToEnd();
        p.StandardError.ReadToEnd();
        if (!p.WaitForExit(30_000)) { try { p.Kill(); } catch { } return -1; }
        return p.ExitCode;
    }
}
