using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace ZeroLeakage.UI.Services;

public sealed record DefenderStatus(
    bool Available,
    bool RealTimeProtection,
    bool AntivirusEnabled,
    string RunningMode,
    string SignatureVersion,
    DateTime? SignaturesUpdated,
    DateTime? LastQuickScan,
    DateTime? LastFullScan,
    string? Error)
{
    public DateTime? LastScan => LastQuickScan > LastFullScan || LastFullScan is null ? LastQuickScan : LastFullScan;
    public static DefenderStatus Unavailable(string error) => new(false, false, false, "", "", null, null, null, error);
}

/// <summary>One Microsoft Defender detection (threat history entry).</summary>
public sealed record DefenderDetection(
    string ThreatId,
    string ThreatName,
    int SeverityId,
    DateTime DetectedAt,
    IReadOnlyList<string> Resources,
    int StatusId,
    bool IsActive)
{
    public string SeverityText => SeverityId switch { 1 => "LOW", 2 => "MODERATE", 4 => "HIGH", 5 => "SEVERE", _ => "UNKNOWN" };

    public string StatusText => StatusId switch
    {
        1 => "Detected",
        2 => "Cleaned",
        3 => "Quarantined",
        4 => "Removed",
        5 => "Allowed",
        6 => "Blocked",
        102 => "Quarantine failed",
        103 => "Remove failed",
        104 => "Allow failed",
        105 => "Abandoned",
        107 => "Block failed",
        _ => IsActive ? "Active" : "Resolved",
    };

    public bool IsQuarantined => StatusId == 3;
    public bool NeedsAction => IsActive || StatusId is 1 or 102 or 103 or 105 or 107;
    public string PrimaryResource => Resources.FirstOrDefault() ?? "(no file recorded)";
    public string FileName => Path.GetFileName(PrimaryResource) is { Length: > 0 } n ? n : PrimaryResource;
    public string DateText => DetectedAt.ToLocalTime().ToString("dd MMM yyyy · HH:mm");
}

/// <summary>
/// DeepScan back-end: drives the Microsoft Defender engine that ships with Windows.
/// Status, threat history and scans work as a normal user; removing or restoring a threat asks for admin (UAC).
/// Nothing here is simulated: every number and detection comes from Defender itself.
/// </summary>
public static class DefenderService
{
    private static readonly string MpCmdRun =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");

    private static readonly object Gate = new();
    public static DefenderStatus? LastStatus { get; private set; }
    public static IReadOnlyList<DefenderDetection> LastDetections { get; private set; } = Array.Empty<DefenderDetection>();

    public static event EventHandler? Updated;

    // ───────────────────────── status & history ─────────────────────────
    public static async Task<DefenderStatus> GetStatusAsync()
    {
        const string script =
            "$s = Get-MpComputerStatus -ErrorAction Stop; " +
            "function D($d) { if ($d -and $d.Year -gt 1970) { $d.ToUniversalTime().ToString('o') } else { $null } }; " +
            "[pscustomobject]@{ Mode=[string]$s.AMRunningMode; Rtp=[bool]$s.RealTimeProtectionEnabled; Av=[bool]$s.AntivirusEnabled; " +
            "Sig=[string]$s.AntivirusSignatureVersion; SigAt=(D $s.AntivirusSignatureLastUpdated); " +
            "Quick=(D $s.QuickScanEndTime); Full=(D $s.FullScanEndTime) } | ConvertTo-Json -Compress";
        var (ok, output) = await RunPowerShellAsync(script);
        DefenderStatus status;
        if (!ok || string.IsNullOrWhiteSpace(output))
        {
            status = DefenderStatus.Unavailable(FirstLine(output) ?? "Microsoft Defender is not available on this PC.");
        }
        else
        {
            try
            {
                using var doc = JsonDocument.Parse(output);
                var r = doc.RootElement;
                status = new DefenderStatus(true, r.GetProperty("Rtp").GetBoolean(), r.GetProperty("Av").GetBoolean(),
                    r.GetProperty("Mode").GetString() ?? "", r.GetProperty("Sig").GetString() ?? "",
                    Date(r, "SigAt"), Date(r, "Quick"), Date(r, "Full"), null);
            }
            catch (Exception ex) { status = DefenderStatus.Unavailable(ex.Message); }
        }
        lock (Gate) LastStatus = status;
        Updated?.Invoke(null, EventArgs.Empty);
        return status;
    }

    public static async Task<IReadOnlyList<DefenderDetection>> GetDetectionsAsync()
    {
        const string script =
            "$t = @{}; Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $t[[string]$_.ThreatID] = $_ }; " +
            "$out = @(Get-MpThreatDetection -ErrorAction Stop | ForEach-Object { $th = $t[[string]$_.ThreatID]; " +
            "[pscustomobject]@{ Id=[string]$_.ThreatID; Name=[string]$th.ThreatName; Sev=[int]$th.SeverityID; " +
            "At=$_.InitialDetectionTime.ToUniversalTime().ToString('o'); Res=@($_.Resources | ForEach-Object { [string]$_ }); " +
            "Status=[int]$_.ThreatStatusID; Active=[bool]$th.IsActive } }); " +
            "ConvertTo-Json -InputObject $out -Depth 4 -Compress";
        var (ok, output) = await RunPowerShellAsync(script);
        var list = new List<DefenderDetection>();
        if (ok && !string.IsNullOrWhiteSpace(output))
        {
            try
            {
                using var doc = JsonDocument.Parse(output);
                var items = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToList() : new() { doc.RootElement };
                foreach (var e in items)
                {
                    var res = e.TryGetProperty("Res", out var ra) && ra.ValueKind == JsonValueKind.Array
                        ? ra.EnumerateArray().Select(x => CleanResource(x.GetString() ?? "")).Where(x => x.Length > 0).ToList()
                        : new List<string>();
                    var name = e.GetProperty("Name").GetString();
                    list.Add(new DefenderDetection(
                        e.GetProperty("Id").GetString() ?? "",
                        string.IsNullOrEmpty(name) ? "Unknown threat" : name,
                        e.GetProperty("Sev").GetInt32(),
                        Date(e, "At") ?? DateTime.UtcNow,
                        res,
                        e.GetProperty("Status").GetInt32(),
                        e.GetProperty("Active").GetBoolean()));
                }
            }
            catch (Exception ex) { Debug.WriteLine(ex); }
        }
        list.Sort((a, b) => b.DetectedAt.CompareTo(a.DetectedAt));
        lock (Gate) LastDetections = list;
        Updated?.Invoke(null, EventArgs.Empty);
        return list;
    }

    /// <summary>Refreshes status + history every few minutes for the dashboard card.</summary>
    public static void StartBackgroundRefresh()
    {
        _ = Task.Run(async () =>
        {
            while (true)
            {
                try { await GetStatusAsync(); await GetDetectionsAsync(); }
                catch (Exception ex) { Debug.WriteLine(ex); }
                await Task.Delay(TimeSpan.FromMinutes(3));
            }
        });
    }

    // ───────────────────────── scanning ─────────────────────────
    public sealed record ScanOutcome(bool Completed, IReadOnlyList<DefenderDetection> NewDetections, TimeSpan Duration, string Message);

    /// <summary>Runs a Defender quick (1) or full (2) scan. Reports elapsed time; Defender does not expose a percentage.</summary>
    /// <param name="path">When set, a custom scan of just this file or folder (ScanType 3).</param>
    public static async Task<ScanOutcome> ScanAsync(bool full, IProgress<TimeSpan> elapsed, CancellationToken ct, string? path = null)
    {
        if (!File.Exists(MpCmdRun)) return new(false, Array.Empty<DefenderDetection>(), TimeSpan.Zero, "Microsoft Defender command-line tool not found.");
        var started = DateTime.UtcNow;
        var args = path is null ? $"-Scan -ScanType {(full ? 2 : 1)}" : $"-Scan -ScanType 3 -File \"{path.TrimEnd('\\')}\"";
        var psi = new ProcessStartInfo(MpCmdRun, args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        using var proc = Process.Start(psi)!;
        var stdout = proc.StandardOutput.ReadToEndAsync();
        _ = proc.StandardError.ReadToEndAsync();

        using var ticker = new PeriodicTimer(TimeSpan.FromSeconds(1));
        var exit = proc.WaitForExitAsync();
        try
        {
            while (!exit.IsCompleted)
            {
                elapsed.Report(DateTime.UtcNow - started);
                await Task.WhenAny(exit, ticker.WaitForNextTickAsync(ct).AsTask());
                ct.ThrowIfCancellationRequested();
            }
        }
        catch (OperationCanceledException)
        {
            try { Process.Start(new ProcessStartInfo(MpCmdRun, "-Scan -Cancel") { UseShellExecute = false, CreateNoWindow = true })?.WaitForExit(10_000); } catch { }
            try { if (!proc.HasExited) proc.Kill(); } catch { }
            throw;
        }

        var text = await stdout;
        var duration = DateTime.UtcNow - started;
        var detections = await GetDetectionsAsync();
        await GetStatusAsync();
        var fresh = detections.Where(d => d.DetectedAt >= started.AddSeconds(-5)).ToList();

        if (proc.ExitCode != 0 && fresh.Count == 0)
        {
            var msg = FirstLine(text) ?? $"Defender exited with code {proc.ExitCode}.";
            if (text.Contains("0x80070005", StringComparison.OrdinalIgnoreCase)) msg = "Defender refused the scan (access denied).";
            if (text.Contains("0x800106ba", StringComparison.OrdinalIgnoreCase) || text.Contains("not running", StringComparison.OrdinalIgnoreCase))
                msg = "Microsoft Defender is turned off or replaced by another antivirus.";
            return new(false, fresh, duration, msg);
        }
        return new(true, fresh, duration, fresh.Count == 0 ? "No threats found" : $"{fresh.Count} threat(s) found");
    }

    // ───────────────────────── signature (definitions) update ─────────────────────────
    public sealed record SignatureUpdateOutcome(bool Ok, string Message, DefenderStatus Status);

    /// <summary>
    /// Asks Defender to fetch the latest security intelligence (MpCmdRun -SignatureUpdate). That works as a normal
    /// user on most PCs; if Defender answers "access denied" we retry with an elevated Update-MpSignature (UAC prompt).
    /// </summary>
    public static async Task<SignatureUpdateOutcome> UpdateSignaturesAsync(CancellationToken ct = default)
    {
        var before = LastStatus?.SignatureVersion;
        if (!File.Exists(MpCmdRun))
            return new(false, "Microsoft Defender command-line tool not found.", await GetStatusAsync());

        int exitCode;
        string text;
        try
        {
            var psi = new ProcessStartInfo(MpCmdRun, "-SignatureUpdate")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            using var proc = Process.Start(psi)!;
            var stdout = proc.StandardOutput.ReadToEndAsync();
            var stderr = proc.StandardError.ReadToEndAsync();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMinutes(10));
            try { await proc.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                try { if (!proc.HasExited) proc.Kill(); } catch { }
                if (ct.IsCancellationRequested) throw;
                return new(false, "Definition update timed out after 10 minutes.", await GetStatusAsync());
            }
            exitCode = proc.ExitCode;
            text = (await stdout) + "\n" + (await stderr);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            exitCode = -1;
            text = ex.Message;
        }

        bool ok = exitCode == 0;
        string message;
        if (!ok && (text.Contains("0x80070005", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("access is denied", StringComparison.OrdinalIgnoreCase) || exitCode == 5))
        {
            ok = await RunElevatedAsync("Update-MpSignature -ErrorAction Stop");
            message = ok ? "" : "Not updated: administrator permission was declined or Defender reported an error.";
        }
        else if (!ok)
        {
            message = text.Contains("0x8024402c", StringComparison.OrdinalIgnoreCase) || text.Contains("0x80072ee7", StringComparison.OrdinalIgnoreCase)
                ? "Defender could not reach the update server. Check your connection."
                : text.Contains("0x800106ba", StringComparison.OrdinalIgnoreCase)
                    ? "Microsoft Defender is turned off or replaced by another antivirus."
                    : FirstLine(text) ?? $"Defender exited with code {exitCode}.";
        }
        else message = "";

        var status = await GetStatusAsync();
        if (ok)
        {
            message = !string.IsNullOrEmpty(before) && before == status.SignatureVersion
                ? $"Definitions already up to date · {status.SignatureVersion}"
                : $"Definitions updated · {status.SignatureVersion}";
        }
        return new(ok, message, status);
    }

    // ───────────────────────── actions (need admin) ─────────────────────────
    /// <summary>Removes every active threat Defender knows about (Remove-MpThreat). Shows a UAC prompt.</summary>
    public static Task<bool> RemoveActiveThreatsAsync() => RunElevatedAsync("Remove-MpThreat -ErrorAction Stop");

    /// <summary>Restores a quarantined threat by name (MpCmdRun -Restore). Shows a UAC prompt.</summary>
    public static Task<bool> RestoreAsync(DefenderDetection d)
    {
        var name = d.ThreatName.Replace("'", "''");
        return RunElevatedAsync($"& '{MpCmdRun}' -Restore -Name '{name}' -All; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}");
    }

    public static void OpenWindowsSecurity(string page = "threat")
    {
        try { Process.Start(new ProcessStartInfo($"windowsdefender://{page}") { UseShellExecute = true }); }
        catch (Exception ex) { Debug.WriteLine(ex); }
    }

    // ───────────────────────── helpers ─────────────────────────
    private static async Task<bool> RunElevatedAsync(string script)
    {
        try
        {
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            using var p = Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}")
            {
                UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (p is null) return false;
            await p.WaitForExitAsync();
            return p.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception) { return false; }   // UAC declined
        finally { _ = GetDetectionsAsync(); }
    }

    private static async Task<(bool Ok, string Output)> RunPowerShellAsync(string script)
    {
        try
        {
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes("$ProgressPreference='SilentlyContinue'; " + script));
            var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEndAsync();
            var error = p.StandardError.ReadToEndAsync();
            await p.WaitForExitAsync();
            var o = (await output).Trim();
            return p.ExitCode == 0 ? (true, o) : (false, (await error).Trim());
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static DateTime? Date(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && DateTime.TryParse(v.GetString(), null,
            System.Globalization.DateTimeStyles.RoundtripKind, out var d) ? d : null;

    private static string CleanResource(string r)
    {
        // Defender prefixes resources with their type, e.g. "file:_C:\path\x.exe", "regkey:_HKLM\...".
        int i = r.IndexOf(":_", StringComparison.Ordinal);
        return i is > 0 and < 12 ? r[(i + 2)..] : r;
    }

    private static string? FirstLine(string? s) =>
        s?.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
}
