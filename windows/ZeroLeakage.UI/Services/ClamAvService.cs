using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace ZeroLeakage.UI.Services;

/// <summary>One file ClamAV flagged.</summary>
public sealed record ClamFinding(string Path, string Signature);

/// <summary>Live progress of a ClamAV scan.</summary>
public readonly record struct ClamProgress(long FilesScanned, string CurrentPath, int Found, string Stage);

/// <summary>
/// Optional second engine: ClamAV (open source, Cisco Talos), installed per user on first use.
/// ClamAV on Windows has no on-access scanning, so it only runs scans you ask for; Microsoft Defender
/// stays the always-on shield. Downloads come only from Cisco's official GitHub releases and are checked
/// (SHA-256 published by GitHub + Authenticode signature by Cisco) before anything runs.
/// </summary>
public static class ClamAvService
{
    public static string Root { get; } = Path.Combine(UiSettingsStore.Directory, "clamav");
    private static string BinDir => Path.Combine(Root, "bin");
    public static string DatabaseDir => Path.Combine(Root, "db");
    private static string ConfigFile => Path.Combine(Root, "freshclam.conf");
    private static string VersionFile => Path.Combine(Root, "engine-version.txt");

    /// <summary>The installed engine's release tag, e.g. "clamav-1.4.2" (null if unknown).</summary>
    public static string? InstalledTag => File.Exists(VersionFile) ? File.ReadAllText(VersionFile).Trim() : null;

    private const string ReleasesApi = "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest";
    private static readonly HttpClient Http = CreateHttp();

    private static HttpClient CreateHttp()
    {
        var h = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        h.DefaultRequestHeaders.UserAgent.ParseAdd("ZeroLeakage-ClamAV-Installer");
        return h;
    }

    public static string? ClamScanPath => FindExe("clamscan.exe");
    public static string? FreshClamPath => FindExe("freshclam.exe");
    public static bool IsInstalled => ClamScanPath is not null && FreshClamPath is not null;

    public static bool HasDatabase =>
        Directory.Exists(DatabaseDir) &&
        Directory.EnumerateFiles(DatabaseDir).Any(f => Path.GetFileName(f).StartsWith("main.", StringComparison.OrdinalIgnoreCase)) &&
        Directory.EnumerateFiles(DatabaseDir).Any(f => Path.GetFileName(f).StartsWith("daily.", StringComparison.OrdinalIgnoreCase));

    public static DateTime? DatabaseUpdated =>
        HasDatabase ? Directory.EnumerateFiles(DatabaseDir).Max(f => File.GetLastWriteTime(f)) : null;

    private static string? FindExe(string name)
    {
        if (!Directory.Exists(BinDir)) return null;
        return Directory.EnumerateFiles(BinDir, name, SearchOption.AllDirectories).FirstOrDefault();
    }

    // ───────────────────────── install ─────────────────────────

    /// <summary>Downloads and verifies the latest official ClamAV for Windows x64, then fetches signatures.</summary>
    public static async Task<string> InstallAsync(IProgress<string> stage, CancellationToken ct)
    {
        var tag = await InstallEngineAsync(stage, ct);
        var update = await UpdateDatabaseAsync(stage, ct);
        return $"ClamAV {Pretty(tag)} installed. {update}";
    }

    /// <summary>
    /// Keeps ClamAV current: upgrades the engine when Cisco has published a newer release, then updates
    /// the signatures. Safe to call daily.
    /// </summary>
    public static async Task<string> UpdateAllAsync(IProgress<string> stage, CancellationToken ct)
    {
        string engineMsg;
        try
        {
            stage.Report("Checking for a newer ClamAV engine…");
            var latest = await LatestTagAsync(ct);
            if (InstalledTag is null || !string.Equals(latest, InstalledTag, StringComparison.OrdinalIgnoreCase))
            {
                var tag = await InstallEngineAsync(stage, ct);
                engineMsg = $"Engine updated to {Pretty(tag)}.";
            }
            else engineMsg = $"Engine {Pretty(latest)} is current.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            engineMsg = "Engine check failed (" + ex.Message + ").";
        }
        var db = await UpdateDatabaseAsync(stage, ct);
        return engineMsg + " " + db;
    }

    private static string Pretty(string tag) => tag.Replace("clamav-", "", StringComparison.OrdinalIgnoreCase);

    private static async Task<string> LatestTagAsync(CancellationToken ct)
    {
        using var rel = JsonDocument.Parse(await Http.GetStringAsync(ReleasesApi, ct));
        return rel.RootElement.GetProperty("tag_name").GetString() ?? "";
    }

    /// <summary>Downloads, verifies and swaps in the latest engine; returns its release tag.</summary>
    private static async Task<string> InstallEngineAsync(IProgress<string> stage, CancellationToken ct)
    {
        stage.Report("Finding the latest ClamAV release…");
        using var rel = JsonDocument.Parse(await Http.GetStringAsync(ReleasesApi, ct));
        string tag = rel.RootElement.GetProperty("tag_name").GetString() ?? "?";
        JsonElement? asset = null;
        foreach (var a in rel.RootElement.GetProperty("assets").EnumerateArray())
        {
            var n = a.GetProperty("name").GetString() ?? "";
            if (n.EndsWith(".win.x64.zip", StringComparison.OrdinalIgnoreCase)) { asset = a; break; }
        }
        if (asset is not { } zipAsset) throw new InvalidOperationException($"ClamAV {tag} has no Windows x64 download.");
        string url = zipAsset.GetProperty("browser_download_url").GetString()!;
        long size = zipAsset.GetProperty("size").GetInt64();
        string? digest = zipAsset.TryGetProperty("digest", out var d) ? d.GetString() : null;
        if (!url.StartsWith("https://github.com/Cisco-Talos/clamav/releases/download/", StringComparison.Ordinal))
            throw new InvalidOperationException("Unexpected download location for ClamAV.");

        Directory.CreateDirectory(Root);
        string zipPath = Path.Combine(Root, "clamav-download.zip");
        stage.Report($"Downloading ClamAV {tag.Replace("clamav-", "")} ({size / 1_048_576.0:0} MB)…");
        await using (var src = await Http.GetStreamAsync(url, ct))
        await using (var dst = File.Create(zipPath))
            await src.CopyToAsync(dst, ct);
        if (new FileInfo(zipPath).Length != size) throw new InvalidOperationException("The ClamAV download was incomplete.");

        // Integrity anchor: the SHA-256 GitHub publishes for Cisco-Talos's release asset (fetched over HTTPS).
        // Cisco's Windows zips aren't Authenticode-signed (they ship GPG .sig files), so without a published
        // hash we refuse rather than install something we can't check.
        if (digest is not { } dg || !dg.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(zipPath);
            throw new InvalidOperationException("GitHub didn't publish a SHA-256 for this ClamAV download, so it can't be verified. Nothing was installed.");
        }
        {
            stage.Report("Checking the download's SHA-256…");
            await using var fs = File.OpenRead(zipPath);
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(fs, ct));
            if (!hash.Equals(dg[7..], StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(zipPath);
                throw new InvalidOperationException("The ClamAV download didn't match its published SHA-256. Nothing was installed.");
            }
        }

        stage.Report("Unpacking…");
        string staging = Path.Combine(Root, "bin-new");
        if (Directory.Exists(staging)) Directory.Delete(staging, true);
        ZipFile.ExtractToDirectory(zipPath, staging);
        File.Delete(zipPath);

        stage.Report("Checking the ClamAV programs…");
        foreach (var exe in new[] { "clamscan.exe", "freshclam.exe" })
        {
            var path = Directory.EnumerateFiles(staging, exe, SearchOption.AllDirectories).FirstOrDefault()
                       ?? throw new InvalidOperationException($"{exe} is missing from the ClamAV package.");
            // If a future build is Authenticode-signed, the signature must be valid and Cisco's.
            if (Authenticode.HasSignature(path) && (!Authenticode.IsTrusted(path, out var signer) || !signer.Contains("Cisco", StringComparison.OrdinalIgnoreCase)))
            {
                Directory.Delete(staging, true);
                throw new InvalidOperationException($"{exe} carries a signature that isn't a valid Cisco one. Nothing was installed.");
            }
        }
        if (Directory.Exists(BinDir)) Directory.Delete(BinDir, true);
        Directory.Move(staging, BinDir);
        await File.WriteAllTextAsync(VersionFile, tag, ct);
        return tag;
    }

    public static void Uninstall()
    {
        if (Directory.Exists(Root)) Directory.Delete(Root, true);
    }

    // ───────────────────────── signatures ─────────────────────────

    /// <summary>Runs freshclam (ClamAV's official updater). The first run downloads ~300 MB.</summary>
    public static async Task<string> UpdateDatabaseAsync(IProgress<string> stage, CancellationToken ct)
    {
        var fresh = FreshClamPath ?? throw new InvalidOperationException("ClamAV isn't installed.");
        Directory.CreateDirectory(DatabaseDir);
        // Minimal config: official mirror only. Paths are passed on the command line (they may contain spaces).
        await File.WriteAllTextAsync(ConfigFile, "DatabaseMirror database.clamav.net\r\nConnectTimeout 30\r\nReceiveTimeout 0\r\n", ct);
        stage.Report(HasDatabase ? "Updating ClamAV signatures…" : "Downloading ClamAV signatures (about 300 MB, first time only)…");
        var (code, output) = await RunAsync(fresh, $"--config-file=\"{ConfigFile}\" --datadir=\"{DatabaseDir}\" --stdout --no-warnings", line =>
        {
            var l = line.Trim();
            if (l.Contains("updated", StringComparison.OrdinalIgnoreCase) || l.Contains("up-to-date", StringComparison.OrdinalIgnoreCase) ||
                l.StartsWith("Retrieving", StringComparison.OrdinalIgnoreCase) || l.Contains("Downloading", StringComparison.OrdinalIgnoreCase))
                stage.Report(l.Length > 110 ? l[..110] + "…" : l);
        }, ct);
        if (code != 0 && !HasDatabase)
            throw new InvalidOperationException("Couldn't download ClamAV signatures: " + LastMeaningfulLine(output));
        return code == 0 ? "Signatures are up to date." : "Signature update had a problem (" + LastMeaningfulLine(output) + "); the existing signatures are still used.";
    }

    /// <summary>"ClamAV 1.4.2 · signatures 27512 (22 Nov 2026)" from clamscan --version.</summary>
    public static async Task<string?> VersionAsync()
    {
        var scan = ClamScanPath;
        if (scan is null) return null;
        var (_, output) = await RunAsync(scan, $"--version --database=\"{DatabaseDir}\"", null, CancellationToken.None);
        var parts = output.Trim().Split('/');
        if (parts.Length >= 3) return $"{parts[0].Trim()} · signatures {parts[1].Trim()} ({parts[2].Trim()})";
        return output.Trim();
    }

    // ───────────────────────── scanning ─────────────────────────

    /// <summary>Downloads, Desktop, temp and startup folders: where new malware usually lands.</summary>
    public static IReadOnlyList<string> QuickScanPaths()
    {
        string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var list = new[]
        {
            Path.Combine(user, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        };
        return list.Where(p => !string.IsNullOrEmpty(p) && Directory.Exists(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static IReadOnlyList<string> FullScanPaths() =>
        DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady).Select(d => d.RootDirectory.FullName).ToList();

    /// <summary>Scans <paramref name="paths"/> and returns what ClamAV found (files are not touched here).</summary>
    public static async Task<(IReadOnlyList<ClamFinding> Found, long Files, string? Error)> ScanAsync(
        IReadOnlyList<string> paths, IProgress<ClamProgress> progress, CancellationToken ct, string? databaseDir = null)
    {
        var scan = ClamScanPath ?? throw new InvalidOperationException("ClamAV isn't installed.");
        var db = databaseDir ?? DatabaseDir;
        if (databaseDir is null && !HasDatabase) throw new InvalidOperationException("ClamAV has no signatures yet: update them first.");

        var args = new StringBuilder($"--database=\"{db}\" --recursive --stdout --no-summary --max-filesize=200M --max-scansize=400M");
        args.Append($" --exclude-dir=\"{Regex.Escape(QuarantineVault.Folder)}\"");
        foreach (var p in paths) args.Append(" \"").Append(p.TrimEnd('\\')).Append('"');

        var found = new List<ClamFinding>();
        long files = 0;
        string? lastError = null;
        var lastReport = DateTime.MinValue;
        progress.Report(new ClamProgress(0, "Loading ClamAV signatures (takes ~20 s)…", 0, "loading"));
        var (code, output) = await RunAsync(scan, args.ToString(), line =>
        {
            var parsed = ParseLine(line);
            if (parsed is null) return;
            var (path, result) = parsed.Value;
            if (result == "OK" || result == "Empty file" || result.StartsWith("Excluded", StringComparison.Ordinal)) files++;
            else if (result.EndsWith(" FOUND", StringComparison.Ordinal))
            {
                files++;
                lock (found) found.Add(new ClamFinding(path, result[..^6].Trim()));
            }
            else if (result.Contains("ERROR", StringComparison.OrdinalIgnoreCase) || result.Contains("Can't", StringComparison.OrdinalIgnoreCase)) lastError = result;
            if ((DateTime.UtcNow - lastReport).TotalMilliseconds > 150)
            {
                lastReport = DateTime.UtcNow;
                progress.Report(new ClamProgress(files, path, found.Count, "scanning"));
            }
        }, ct);
        progress.Report(new ClamProgress(files, "", found.Count, "done"));
        // 0 = clean, 1 = found, 2 = some errors (usually unreadable files; results are still valid)
        if (code is not (0 or 1 or 2)) return (found, files, "ClamAV stopped unexpectedly: " + LastMeaningfulLine(output));
        if (code == 2 && files == 0) return (found, files, "ClamAV couldn't scan: " + LastMeaningfulLine(output));
        return (found, files, null);
    }

    /// <summary>Parses "C:\path\file.exe: Win.Trojan.X-1 FOUND" (paths may themselves contain ": ").</summary>
    public static (string Path, string Result)? ParseLine(string line)
    {
        line = line.TrimEnd();
        int i = line.LastIndexOf(": ", StringComparison.Ordinal);
        if (i <= 1) return null;
        return (line[..i], line[(i + 2)..]);
    }

    // ───────────────────────── process helper ─────────────────────────

    private static async Task<(int Code, string Output)> RunAsync(string exe, string args, Action<string>? onLine, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Path.GetDirectoryName(exe)!,
        };
        using var p = new Process { StartInfo = psi };
        var all = new StringBuilder();
        void Handle(string? l)
        {
            if (l is null) return;
            lock (all) all.AppendLine(l);
            onLine?.Invoke(l);
        }
        p.OutputDataReceived += (_, e) => Handle(e.Data);
        p.ErrorDataReceived += (_, e) => Handle(e.Data);
        p.Start();
        p.PriorityClass = ProcessPriorityClass.BelowNormal;   // keep the PC responsive during scans
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        try
        {
            await p.WaitForExitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw;
        }
        p.WaitForExit();   // flush async output
        return (p.ExitCode, all.ToString());
    }

    private static string LastMeaningfulLine(string output) =>
        output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.Length > 0 && !l.StartsWith("---", StringComparison.Ordinal)) ?? "unknown error";
}

/// <summary>WinVerifyTrust check of an executable's Authenticode signature.</summary>
internal static class Authenticode
{
    public static bool HasSignature(string file)
    {
        try
        {
#pragma warning disable SYSLIB0057
            _ = X509Certificate.CreateFromSignedFile(file);
#pragma warning restore SYSLIB0057
            return true;
        }
        catch { return false; }
    }

    public static bool IsTrusted(string file, out string signer)
    {
        signer = "unsigned";
        try
        {
#pragma warning disable SYSLIB0057
            signer = X509Certificate.CreateFromSignedFile(file).Subject;
#pragma warning restore SYSLIB0057
        }
        catch { return false; }
        return Verify(file) == 0;
    }

    private static readonly Guid ActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;          // 2 = no UI
        public uint fdwRevocationChecks; // 0 = none (whole-chain check below)
        public uint dwUnionChoice;       // 1 = file
        public IntPtr pFile;
        public uint dwStateAction;       // 0 = ignore
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;         // 0x80 = revocation check chain exclude root (0x80)
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WinTrustData data);

    private static int Verify(string file)
    {
        var fileInfo = new WinTrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(), pcwszFilePath = file };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2, fdwRevocationChecks = 0, dwUnionChoice = 1, pFile = pFile, dwProvFlags = 0x80,
            };
            return WinVerifyTrust(new IntPtr(-1), ActionGenericVerifyV2, ref data);
        }
        finally
        {
            Marshal.FreeHGlobal(pFile);
        }
    }
}
