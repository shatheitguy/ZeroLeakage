using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace ZeroLeakage.Core.Guard;

public sealed record FeedDefinition(string Id, string Name, string Url, string Homepage, string Description, bool DefaultEnabled = true)
{
    /// <summary>Bearer token for the ZeroLeakage Server bouncer feed (never logged).</summary>
    public string? BearerToken { get; init; }
    public bool IsServer { get; init; }
}

/// <summary>
/// Public threat-IP feeds that need no account. Each URL was checked with curl when Guard was added
/// (all six answered 200 with plain-text address lists).
/// </summary>
public static class FeedCatalog
{
    public const string ServerFeedId = "zeroleakage-server";

    public static readonly IReadOnlyList<FeedDefinition> Builtin = new FeedDefinition[]
    {
        new("spamhaus-drop", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", "https://www.spamhaus.org/drop/",
            "Hijacked and criminal-run netblocks. Tiny, zero false positives."),
        new("firehol-level1", "FireHOL level 1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            "https://iplists.firehol.org/", "Attacks, malware and bogons from several sources, tuned for minimum false positives."),
        new("feodo", "abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "https://feodotracker.abuse.ch/",
            "Botnet command-and-control servers (Dridex, Emotet, QakBot…)."),
        new("et-compromised", "Emerging Threats compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "https://rules.emergingthreats.net/", "Known compromised hosts from Proofpoint Emerging Threats."),
        new("blocklist-de", "blocklist.de (all)", "https://lists.blocklist.de/lists/all.txt", "https://www.blocklist.de/",
            "IPs reported for SSH, mail, web and RDP attacks in the last 48 hours."),
        new("cins-army", "CINS Army", "https://cinsscore.com/list/ci-badguys.txt", "https://cinsscore.com/",
            "Sentinel IPS's list of hosts with a poor reputation score."),
    };

    public static FeedDefinition? Find(string id) => Builtin.FirstOrDefault(f => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    public static FeedDefinition ServerFeed(Uri server, string token, string serverName) =>
        new(ServerFeedId, $"ZeroLeakage Server · {serverName}", Shared.Link.ServerAddress.Combine(server, "api/v1/guard/blocklist.txt").AbsoluteUri,
            server.AbsoluteUri, "Your own server's Guard blocklist (bouncer mode).") { BearerToken = token, IsServer = true };
}

public enum FetchStatus { Updated, NotModified, Failed }

public sealed record FeedFetchResult(FetchStatus Status, string? Text = null, string? ETag = null, string? LastModified = null, string? Error = null);

public interface IFeedSource
{
    Task<FeedFetchResult> FetchAsync(FeedDefinition feed, string? etag, string? lastModified, CancellationToken ct);
}

/// <summary>Downloads feeds over HTTPS with conditional requests; no cookies, no identifying headers.</summary>
public sealed class HttpFeedSource : IFeedSource, IDisposable
{
    public const long MaxBytes = 32L * 1024 * 1024;
    private readonly HttpClient _http;

    public HttpFeedSource(HttpMessageHandler? handler = null)
    {
        _http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            UseCookies = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
        })
        { Timeout = TimeSpan.FromSeconds(90) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("ZeroLeakage-Guard");
    }

    public async Task<FeedFetchResult> FetchAsync(FeedDefinition feed, string? etag, string? lastModified, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, feed.Url);
            if (feed.BearerToken is { Length: > 0 } token) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            if (etag is not null && EntityTagHeaderValue.TryParse(etag, out var tag)) req.Headers.IfNoneMatch.Add(tag);
            if (lastModified is not null && DateTimeOffset.TryParse(lastModified, out var lm)) req.Headers.IfModifiedSince = lm;

            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.NotModified) return new(FetchStatus.NotModified, ETag: etag, LastModified: lastModified);
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                return new(FetchStatus.Failed, Error: $"HTTP {(int)resp.StatusCode}: the server refused the key");
            if (!resp.IsSuccessStatusCode) return new(FetchStatus.Failed, Error: $"HTTP {(int)resp.StatusCode}");
            if (resp.Content.Headers.ContentLength > MaxBytes) return new(FetchStatus.Failed, Error: "Feed is larger than 32 MB");

            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var ms = new MemoryStream();
            var buf = new byte[81920];
            int n;
            while ((n = await stream.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
            {
                ms.Write(buf, 0, n);
                if (ms.Length > MaxBytes) return new(FetchStatus.Failed, Error: "Feed is larger than 32 MB");
            }
            var text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
            return new(FetchStatus.Updated, text, resp.Headers.ETag?.ToString(), resp.Content.Headers.LastModified?.ToString("R"));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new(FetchStatus.Failed, Error: "Timed out");
        }
        catch (HttpRequestException ex)
        {
            return new(FetchStatus.Failed, Error: ex.Message);
        }
    }

    public void Dispose() => _http.Dispose();
}
