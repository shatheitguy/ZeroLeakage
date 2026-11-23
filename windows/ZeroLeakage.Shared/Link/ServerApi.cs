using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroLeakage.Shared.Link;

// ───────────────────────── wire format (ZeroLeakage Server /api/v1) ─────────────────────────

/// <summary>Answer to POST /devices/pair (pairing code) and POST /devices/link (username + password).</summary>
public sealed class LinkResponse
{
    public string? Token { get; set; }
    public LinkedDevice? Device { get; set; }
    public ServerInfo? Server { get; set; }
    public ServerUser? User { get; set; }
    /// <summary>ZeroLeakage Server returns the account as a plain "username" string.</summary>
    public string? Username { get; set; }
}

public sealed class LinkedDevice
{
    [JsonConverter(typeof(LenientStringConverter))] public string? Id { get; set; }
    public string? Name { get; set; }
    public string? DohUrl { get; set; }
    public string? DotHost { get; set; }
}

public sealed class ServerInfo
{
    public string? Name { get; set; }
    [JsonConverter(typeof(LenientStringConverter))] public string? Version { get; set; }
    public string? Hostname { get; set; }
}

public sealed class ServerUser
{
    public string? Username { get; set; }
    public string? DisplayName { get; set; }
    public string? Role { get; set; }
}

public sealed class SyncRule
{
    /// <summary>"allow" or "block".</summary>
    public string Kind { get; set; } = "";
    public string Domain { get; set; } = "";
    /// <summary>Unix time in milliseconds; last writer wins.</summary>
    public long UpdatedAt { get; set; }
    public bool Deleted { get; set; }

    public SyncRule Clone() => new() { Kind = Kind, Domain = Domain, UpdatedAt = UpdatedAt, Deleted = Deleted };
}

public sealed class CustomListDto
{
    [JsonConverter(typeof(LenientStringConverter))] public string? Id { get; set; }
    public string? Name { get; set; }
    public string? Url { get; set; }
    public string? Category { get; set; }
}

public sealed class GuardPolicyDto
{
    public bool Enabled { get; set; }
    [JsonPropertyName("dropMaliciousIPs")] public bool DropMaliciousIps { get; set; }
}

/// <summary>The effective policy for this device (admin baseline + the user's own extras).</summary>
public sealed class SyncPolicy
{
    public List<string>? Lists { get; set; }
    public List<CustomListDto>? CustomLists { get; set; }
    public List<string>? Services { get; set; }
    public List<string>? Categories { get; set; }
    public JsonElement? SafeSearch { get; set; }
    public JsonElement? BlockMode { get; set; }
    public JsonElement? Schedules { get; set; }
    public GuardPolicyDto? Guard { get; set; }
    public bool BypassBlocking { get; set; }
}

/// <summary>The admin's network baseline: always wins, can't be weakened from the app.</summary>
public sealed class LockedPolicy
{
    public List<string>? Lists { get; set; }
    public List<string>? Services { get; set; }
    public List<string>? Categories { get; set; }
    public List<string>? BlockDomains { get; set; }
    public JsonElement? SafeSearch { get; set; }
}

/// <summary>The signed-in user's own additions; synced between that user's apps only.</summary>
public sealed class UserPolicy
{
    public List<string> Lists { get; set; } = new();
    public List<CustomListDto> CustomLists { get; set; } = new();
    public List<string> Services { get; set; } = new();
    public List<string> Categories { get; set; } = new();
    public JsonElement? SafeSearch { get; set; }

    public UserPolicy Clone() => new()
    {
        Lists = Lists.ToList(),
        CustomLists = CustomLists.Select(c => new CustomListDto { Id = c.Id, Name = c.Name, Url = c.Url, Category = c.Category }).ToList(),
        Services = Services.ToList(),
        Categories = Categories.ToList(),
        SafeSearch = SafeSearch?.Clone(),
    };
}

public sealed class EffectiveRules
{
    public List<string>? Allow { get; set; }
    public List<string>? Block { get; set; }
}

/// <summary>GET /api/v1/sync.</summary>
public sealed class SyncResponse
{
    public List<SyncRule>? Rules { get; set; }
    [JsonConverter(typeof(LenientStringConverter))] public string? ServerTime { get; set; }
    [JsonConverter(typeof(LenientStringConverter))] public string? DeviceId { get; set; }
    public string? DohUrl { get; set; }
    public string? DotHost { get; set; }
    [JsonConverter(typeof(LenientStringConverter))] public string? PolicyVersion { get; set; }
    public SyncPolicy? Policy { get; set; }
    public EffectiveRules? Effective { get; set; }
    public LockedPolicy? Locked { get; set; }
    public UserPolicy? UserPolicy { get; set; }
    public ServerUser? User { get; set; }
}

/// <summary>PUT /api/v1/sync: the user's rule edits (merged last-writer-wins) and, when changed, their own extras.</summary>
public sealed class SyncPush
{
    public List<SyncRule> Rules { get; set; } = new();
    public UserPolicy? UserPolicy { get; set; }
}

/// <summary>Reads strings, numbers and booleans as text (servers differ on ids and versions).</summary>
public sealed class LenientStringConverter : JsonConverter<string?>
{
    public override bool HandleNull => true;

    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.TokenType switch
    {
        JsonTokenType.String => reader.GetString(),
        JsonTokenType.Number => System.Text.Encoding.UTF8.GetString(reader.HasValueSequence
            ? System.Buffers.BuffersExtensions.ToArray(reader.ValueSequence)
            : reader.ValueSpan.ToArray()),
        JsonTokenType.True => "true",
        JsonTokenType.False => "false",
        JsonTokenType.Null => null,
        _ => SkipAndNull(ref reader),
    };

    private static string? SkipAndNull(ref Utf8JsonReader reader)
    {
        reader.Skip();
        return null;
    }

    public override void Write(Utf8JsonWriter writer, string? value, JsonSerializerOptions options)
    {
        if (value is null) writer.WriteNullValue();
        else writer.WriteStringValue(value);
    }
}

public sealed class ServerApiException : Exception
{
    public ServerApiException(string message, HttpStatusCode? status = null, Exception? inner = null) : base(message, inner) => Status = status;
    public HttpStatusCode? Status { get; }
    public bool IsUnauthorized => Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden;
}

// ───────────────────────── client ─────────────────────────

/// <summary>HTTP client for the ZeroLeakage Server device API. Never logs or echoes passwords or tokens.</summary>
public sealed class ServerApiClient
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;

    public ServerApiClient(HttpClient? http = null) => _http = http ?? CreateHttp();

    public static HttpClient CreateHttp()
    {
        var h = new HttpClient(new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
        })
        {
            Timeout = TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = 32L * 1024 * 1024,
        };
        h.DefaultRequestHeaders.UserAgent.ParseAdd("ZeroLeakage-Windows");
        return h;
    }

    public Task<LinkResponse> PairAsync(Uri server, string code, string deviceName, CancellationToken ct) =>
        PostLinkAsync(server, "api/v1/devices/pair", new { code, deviceName, platform = "windows" },
            "The pairing code is wrong or has expired. Create a new one on your server.", ct);

    public Task<LinkResponse> SignInAsync(Uri server, string username, string password, string deviceName, CancellationToken ct) =>
        PostLinkAsync(server, "api/v1/devices/link", new { username, password, deviceName, platform = "windows" },
            "Wrong username or password.", ct);

    public async Task<SyncResponse> GetSyncAsync(Uri server, string token, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, ServerAddress.Combine(server, "api/v1/sync"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var resp = await SendAsync(req, ct).ConfigureAwait(false);
        await EnsureOk(resp, "This device is no longer authorized on the server. Unlink and link it again.", ct).ConfigureAwait(false);
        return await resp.Content.ReadFromJsonAsync<SyncResponse>(Json, ct).ConfigureAwait(false)
               ?? throw new ServerApiException("The server sent an empty sync answer");
    }

    public async Task PutSyncAsync(Uri server, string token, SyncPush body, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Put, ServerAddress.Combine(server, "api/v1/sync"))
        {
            Content = JsonContent.Create(body, options: Json),
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var resp = await SendAsync(req, ct).ConfigureAwait(false);
        await EnsureOk(resp, "This device is no longer authorized on the server. Unlink and link it again.", ct).ConfigureAwait(false);
    }

    private async Task<LinkResponse> PostLinkAsync(Uri server, string path, object body, string unauthorizedMessage, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, ServerAddress.Combine(server, path))
        {
            Content = JsonContent.Create(body, options: Json),
        };
        using var resp = await SendAsync(req, ct).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotFound)
            throw new ServerApiException("That address didn't answer like a ZeroLeakage Server (404). Check the address.", resp.StatusCode);
        await EnsureOk(resp, unauthorizedMessage, ct).ConfigureAwait(false);
        var link = await resp.Content.ReadFromJsonAsync<LinkResponse>(Json, ct).ConfigureAwait(false);
        if (link is null || string.IsNullOrWhiteSpace(link.Token))
            throw new ServerApiException("The server accepted the request but sent no device token");
        return link;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        try
        {
            return await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct).ConfigureAwait(false);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new ServerApiException("The server didn't answer in time", null, ex);
        }
        catch (HttpRequestException ex)
        {
            throw new ServerApiException($"Can't reach the server: {ex.Message}", null, ex);
        }
    }

    private static async Task EnsureOk(HttpResponseMessage resp, string unauthorizedMessage, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode) return;
        if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new ServerApiException(unauthorizedMessage, resp.StatusCode);
        string? detail = null;
        try
        {
            var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                (doc.RootElement.TryGetProperty("error", out var e) || doc.RootElement.TryGetProperty("message", out e)) &&
                e.ValueKind == JsonValueKind.String)
                detail = e.GetString();
        }
        catch { /* not JSON */ }
        if (detail is { Length: > 200 }) detail = detail[..200];
        throw new ServerApiException($"Server error {(int)resp.StatusCode}{(detail is null ? "" : ": " + detail)}", resp.StatusCode);
    }
}
