using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace ZeroLeakage.Core.Guard;

/// <summary>Runs the Guard engine loop (initial sync, expiry, daily feeds).</summary>
public sealed class GuardWorker : BackgroundService
{
    private readonly GuardEngine _engine;
    private readonly ILogger _log;

    public GuardWorker(GuardEngine engine, ILogger<GuardWorker> log)
    {
        _engine = engine;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try { await _engine.RunAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) { _log.LogCritical(ex, "Guard engine stopped"); throw; }
    }
}

/// <summary>Subscribes to Windows Security event 4625 (failed logon) — needs SYSTEM or Event Log Readers.</summary>
public sealed class SecurityLogWatcher : IHostedService, IDisposable
{
    private static readonly EventLogPropertySelector Selector = new(new[]
    {
        "Event/EventData/Data[@Name='IpAddress']",
        "Event/EventData/Data[@Name='TargetUserName']",
    });

    private readonly GuardEngine _engine;
    private readonly ILogger _log;
    private EventLogWatcher? _watcher;

    public SecurityLogWatcher(GuardEngine engine, ILogger<SecurityLogWatcher> log)
    {
        _engine = engine;
        _log = log;
    }

    public Task StartAsync(CancellationToken ct)
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4625)]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEvent;
            _watcher.Enabled = true;
            _engine.SetScenarioAvailability(GuardEngine.ScenarioBruteForce, true, "Watching Windows Security event 4625");
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            _log.LogWarning(ex, "Can't watch the Security log");
            _engine.SetScenarioAvailability(GuardEngine.ScenarioBruteForce, false, "Can't read the Windows Security log: " + ex.Message);
        }
        return Task.CompletedTask;
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        using var record = e.EventRecord;
        if (record is not EventLogRecord rec) return;
        try
        {
            var values = rec.GetPropertyValues(Selector);
            _engine.OnFailedLogon(values.Count > 0 ? values[0] as string : null, values.Count > 1 ? values[1] as string : null);
        }
        catch (Exception ex) { _log.LogDebug(ex, "Unreadable 4625 event"); }
    }

    public Task StopAsync(CancellationToken ct)
    {
        if (_watcher is not null) _watcher.Enabled = false;
        return Task.CompletedTask;
    }

    public void Dispose() => _watcher?.Dispose();
}

public sealed record FirewallLogEntry(string Action, string Protocol, string SourceIp, int DestinationPort, string Path);

/// <summary>Parses pfirewall.log (W3C extended format, honouring its "#Fields:" header).</summary>
public sealed class FirewallLogParser
{
    private string[] _fields = "date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid".Split(' ');

    public FirewallLogEntry? ParseLine(string line)
    {
        if (line.Length == 0) return null;
        if (line[0] == '#')
        {
            if (line.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
                _fields = line[8..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return null;
        }
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string Get(string name)
        {
            int i = Array.IndexOf(_fields, name);
            return i >= 0 && i < parts.Length ? parts[i] : "";
        }
        var port = int.TryParse(Get("dst-port"), NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : 0;
        return new FirewallLogEntry(Get("action"), Get("protocol"), Get("src-ip"), port, Get("path"));
    }

    /// <summary>Port-scan evidence: a dropped inbound TCP/UDP packet.</summary>
    public static bool IsDroppedInbound(FirewallLogEntry e) =>
        e.Action.Equals("DROP", StringComparison.OrdinalIgnoreCase) &&
        e.Path.Equals("RECEIVE", StringComparison.OrdinalIgnoreCase) &&
        (e.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) || e.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase)) &&
        e.DestinationPort > 0;
}

/// <summary>Tails the Windows Firewall log when dropped-packet logging is on (optional port-scan scenario).</summary>
public sealed class FirewallLogWatcher : BackgroundService
{
    private readonly GuardEngine _engine;
    private readonly ILogger _log;

    public FirewallLogWatcher(GuardEngine engine, ILogger<FirewallLogWatcher> log)
    {
        _engine = engine;
        _log = log;
    }

    /// <summary>Log path and whether any profile logs dropped packets (read-only registry check).</summary>
    public static (string Path, bool DroppedLogging) Locate()
    {
        string path = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log");
        bool dropped = false;
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
        {
            foreach (var root in new[]
                     {
                         @"SOFTWARE\Policies\Microsoft\WindowsFirewall\" + profile + @"\Logging",
                         @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + profile + @"\Logging",
                     })
            {
                using var k = Registry.LocalMachine.OpenSubKey(root);
                if (k is null) continue;
                if (k.GetValue("LogDroppedPackets") is int d && d != 0) dropped = true;
                if (k.GetValue("LogFilePath") is string p && p.Length > 0) path = Environment.ExpandEnvironmentVariables(p);
            }
        }
        return (path, dropped);
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var parser = new FirewallLogParser();
        long offset = -1;
        string? currentPath = null;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var (path, dropped) = Locate();
                if (!dropped || !File.Exists(path))
                {
                    _engine.SetScenarioAvailability(GuardEngine.ScenarioPortScan, false,
                        "Turn on \"Log dropped packets\" in Windows Defender Firewall (Advanced settings → Properties → Logging) to detect port scans.");
                    offset = -1;
                }
                else
                {
                    _engine.SetScenarioAvailability(GuardEngine.ScenarioPortScan, true, "Reading " + path);
                    if (path != currentPath) { currentPath = path; offset = -1; }
                    offset = ReadNew(path, offset, parser);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _engine.SetScenarioAvailability(GuardEngine.ScenarioPortScan, false, "Can't read the firewall log: " + ex.Message);
            }
            catch (Exception ex) { _log.LogWarning(ex, "Firewall log watcher error"); }
            try { await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private long ReadNew(string path, long offset, FirewallLogParser parser)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (offset < 0 || offset > fs.Length) return fs.Length;   // first look or rotated: start at the end
        if (fs.Length - offset > 8 * 1024 * 1024) offset = fs.Length - 8 * 1024 * 1024;
        fs.Seek(offset, SeekOrigin.Begin);
        using var reader = new StreamReader(fs, Encoding.ASCII, false, 64 * 1024, leaveOpen: true);
        string? line;
        long consumed = offset;
        while ((line = reader.ReadLine()) is not null)
        {
            consumed += Encoding.ASCII.GetByteCount(line) + 2;
            var e = parser.ParseLine(line);
            if (e is not null && FirewallLogParser.IsDroppedInbound(e)) _engine.OnDroppedInbound(e.SourceIp, e.DestinationPort);
        }
        return Math.Min(consumed, fs.Length);
    }
}
