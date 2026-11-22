using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace ZeroLeakage.UI.Services;

public enum UpdateState { Unknown, UpToDate, Available, Error }

/// <summary>Result of one look at the latest GitHub release.</summary>
public sealed record UpdateCheckResult(
    UpdateState State,
    Version? LatestVersion,
    string? Tag,
    string? NotesSummary,
    string? ReleasePageUrl,
    string? AssetName,
    string? AssetUrl,
    long AssetSize,
    DateTime CheckedAt,
    string? Error)
{
    public static UpdateCheckResult Failed(string error) =>
        new(UpdateState.Error, null, null, null, null, null, null, 0, DateTime.Now, error);
}

/// <summary>
/// App self-update: reads the latest release of the public GitHub repository, compares it with the running
/// version and, on request, downloads the x64 MSI and hands it to msiexec (the MSI's MajorUpgrade replaces this copy).
/// Only a generic User-Agent is sent; no user or machine information leaves the PC.
/// </summary>
public static class UpdateService
{
    public const string Owner = "shatheitguy";
    public const string Repo = "ZeroLeakage";
    public const string WebsiteUrl = "https://shatheitguy.github.io/ZeroLeakage/";
    public const string GitHubUrl = "https://github.com/shatheitguy/ZeroLeakage";
    public const string ReleasesUrl = "https://github.com/shatheitguy/ZeroLeakage/releases";
    private const string LatestApi = "https://api.github.com/repos/" + Owner + "/" + Repo + "/releases/latest";
    private const string AssetSuffix = "-x64.msi";

    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var c = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 6 })
        {
            Timeout = Timeout.InfiniteTimeSpan,   // per-call timeouts below
        };
        c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("ZeroLeakage-Updater", "1.0"));
        return c;
    }

    // ───────────────────────── running version ─────────────────────────
    /// <summary>"1.1.0" (informational version without the "+commit" suffix).</summary>
    public static string CurrentVersionText { get; } = ReadVersionText();
    public static Version CurrentVersion { get; } = ParseVersion(CurrentVersionText) ?? new Version(0, 0, 0, 0);
    /// <summary>Source revision baked in by the SDK ("+abc1234…"), if any.</summary>
    public static string? SourceRevision { get; } = ReadRevision();

    private static string InformationalVersion =>
        Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "0.0.0";

    private static string ReadVersionText()
    {
        var v = InformationalVersion;
        int plus = v.IndexOf('+');
        return plus >= 0 ? v[..plus] : v;
    }

    private static string? ReadRevision()
    {
        var v = InformationalVersion;
        int plus = v.IndexOf('+');
        if (plus < 0 || plus == v.Length - 1) return null;
        var rev = v[(plus + 1)..];
        return rev.Length > 7 ? rev[..7] : rev;
    }

    /// <summary>Parses "v1.2", "1.2.3-beta" etc. into a normalised 4-part version.</summary>
    public static Version? ParseVersion(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var m = Regex.Match(text.Trim().TrimStart('v', 'V'), @"^\d+(\.\d+){0,3}");
        if (!m.Success || !Version.TryParse(m.Value.Contains('.') ? m.Value : m.Value + ".0", out var v)) return null;
        return new Version(v.Major, v.Minor, Math.Max(v.Build, 0), Math.Max(v.Revision, 0));
    }

    public static string Display(Version v) => v.Revision > 0 ? v.ToString(4) : v.ToString(3);

    // ───────────────────────── check ─────────────────────────
    public static UpdateCheckResult? LastResult { get; private set; }

    public static async Task<UpdateCheckResult> CheckAsync(CancellationToken ct = default)
    {
        UpdateCheckResult result;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(20));
            using var req = new HttpRequestMessage(HttpMethod.Get, LatestApi);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            req.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
            using var resp = await Http.SendAsync(req, cts.Token).ConfigureAwait(false);

            if (resp.StatusCode == HttpStatusCode.NotFound)
                result = UpdateCheckResult.Failed("No published release found on GitHub yet.");
            else if (resp.StatusCode == HttpStatusCode.Forbidden || (int)resp.StatusCode == 429)
                result = UpdateCheckResult.Failed("GitHub rate limit reached. Try again in a little while.");
            else if (!resp.IsSuccessStatusCode)
                result = UpdateCheckResult.Failed($"GitHub answered {(int)resp.StatusCode} {resp.ReasonPhrase}.");
            else
            {
                var json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                result = Parse(json);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            result = UpdateCheckResult.Failed("Timed out reaching GitHub. Check your connection.");
        }
        catch (HttpRequestException ex)
        {
            result = UpdateCheckResult.Failed($"Offline or GitHub unreachable ({ex.HttpRequestError}).");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = UpdateCheckResult.Failed(ex.Message);
        }
        LastResult = result;
        return result;
    }

    private static UpdateCheckResult Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        var tag = r.TryGetProperty("tag_name", out var t) ? t.GetString() : null;
        var latest = ParseVersion(tag);
        if (latest is null) return UpdateCheckResult.Failed($"Could not read the release version (\"{tag}\").");

        string? page = r.TryGetProperty("html_url", out var h) ? h.GetString() : ReleasesUrl;
        string? notes = r.TryGetProperty("body", out var b) && b.ValueKind == JsonValueKind.String ? Summarize(b.GetString()) : null;

        string? assetName = null, assetUrl = null;
        long assetSize = 0;
        if (r.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
        {
            foreach (var a in assets.EnumerateArray())
            {
                var name = a.TryGetProperty("name", out var n) ? n.GetString() : null;
                if (name is null || !name.EndsWith(AssetSuffix, StringComparison.OrdinalIgnoreCase)) continue;
                assetName = name;
                assetUrl = a.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
                assetSize = a.TryGetProperty("size", out var s) && s.TryGetInt64(out var sz) ? sz : 0;
                break;
            }
        }

        var state = latest > CurrentVersion ? UpdateState.Available : UpdateState.UpToDate;
        return new UpdateCheckResult(state, latest, tag, notes, page, assetName, assetUrl, assetSize, DateTime.Now, null);
    }

    /// <summary>First ~300 characters of the release notes, with Markdown noise removed.</summary>
    private static string? Summarize(string? markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown)) return null;
        var lines = markdown.Replace("\r", "").Split('\n')
            .Select(l => Regex.Replace(l, @"^\s*(#+|[-*+]|\d+\.)\s*", "").Trim())
            .Select(l => Regex.Replace(l, @"\*\*|__|`|\[([^\]]*)\]\([^)]*\)", m => m.Groups[1].Success ? m.Groups[1].Value : ""))
            .Where(l => l.Length > 0);
        var text = string.Join(" · ", lines);
        return text.Length <= 300 ? text : text[..300].TrimEnd() + "…";
    }

    // ───────────────────────── download & install ─────────────────────────
    public static string DownloadFolder => Path.Combine(Path.GetTempPath(), "ZeroLeakage-update");

    /// <summary>Downloads the release MSI, checking the byte count against the size GitHub published.</summary>
    public static async Task<string> DownloadAsync(UpdateCheckResult release, IProgress<double> progress, CancellationToken ct)
    {
        if (release.AssetUrl is null || release.AssetName is null)
            throw new InvalidOperationException("This release has no Windows x64 installer attached.");
        var uri = new Uri(release.AssetUrl);
        if (uri.Scheme != Uri.UriSchemeHttps || !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Refusing to download the installer from an unexpected host.");

        Directory.CreateDirectory(DownloadFolder);
        var target = Path.Combine(DownloadFolder, Path.GetFileName(release.AssetName));
        var partial = target + ".part";

        using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            cts.CancelAfter(TimeSpan.FromMinutes(15));
            using var resp = await Http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            long total = resp.Content.Headers.ContentLength ?? release.AssetSize;
            await using (var src = await resp.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false))
            await using (var dst = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                var buffer = new byte[81920];
                long done = 0;
                int read;
                while ((read = await src.ReadAsync(buffer, cts.Token).ConfigureAwait(false)) > 0)
                {
                    await dst.WriteAsync(buffer.AsMemory(0, read), cts.Token).ConfigureAwait(false);
                    done += read;
                    if (total > 0) progress.Report(Math.Min(100, done * 100.0 / total));
                }
            }
        }

        var size = new FileInfo(partial).Length;
        if (release.AssetSize > 0 && size != release.AssetSize)
        {
            TryDelete(partial);
            throw new InvalidDataException($"Download incomplete: got {size:N0} bytes, expected {release.AssetSize:N0}.");
        }
        TryDelete(target);
        File.Move(partial, target);
        return target;
    }

    /// <summary>Starts msiexec on the downloaded MSI. The caller exits the app right after so files can be replaced.</summary>
    public static void LaunchInstaller(string msiPath)
    {
        var log = Path.Combine(DownloadFolder, "install.log");
        Process.Start(new ProcessStartInfo("msiexec.exe", $"/i \"{msiPath}\" /passive /norestart /l*v \"{log}\"")
        {
            UseShellExecute = true,
        });
    }

    public static void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { Debug.WriteLine(ex); }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
