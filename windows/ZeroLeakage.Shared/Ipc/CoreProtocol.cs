using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroLeakage.Shared.Ipc;

/// <summary>
/// Contract for the local named pipe between the desktop app and the ZeroLeakage Core service.
/// One JSON object per line (UTF-8, '\n' terminated), strictly request → response.
/// Secrets (bouncer keys, device tokens) only ever travel app → service; responses never contain them.
/// </summary>
public static class CoreIpc
{
    public const string PipeName = "ZeroLeakage.Core";
    public const string ServiceName = "ZeroLeakageCore";
    public const string ServiceDisplayName = "ZeroLeakage Core";
    public const int MaxMessageBytes = 8 * 1024 * 1024;

    public static readonly JsonSerializerOptions Json = CreateJson();

    private static JsonSerializerOptions CreateJson()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };
        o.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return o;
    }
}

public static class CoreCommands
{
    public const string Status = "status";
    public const string Decisions = "decisions";
    public const string Ban = "ban";
    public const string Unban = "unban";
    public const string Allow = "allow";
    public const string RemoveAllow = "removeAllow";
    public const string SetEnabled = "setEnabled";
    public const string SetFeed = "setFeed";
    public const string SetScenario = "setScenario";
    public const string UpdateFeeds = "updateFeeds";
    /// <summary>Manual bouncer: server URL + bouncer API key (empty URL clears it).</summary>
    public const string SetServer = "setServer";
    /// <summary>Account &amp; sync linked this PC: server URL + device token (used as the bouncer source).</summary>
    public const string SetLink = "setLink";
    public const string ClearLink = "clearLink";
    /// <summary>Server's Guard policy while linked (Guard on/off, server blocklist on/off).</summary>
    public const string SetGuardPolicy = "setGuardPolicy";
    /// <summary>Use the linked server as this PC's DNS (DoH) — off by default.</summary>
    public const string SetDnsMode = "setDnsMode";
}

public sealed class CoreRequest
{
    public int Id { get; set; }
    public string Command { get; set; } = "";
    /// <summary>IP address or CIDR range.</summary>
    public string? Value { get; set; }
    /// <summary>Feed id or scenario id.</summary>
    public string? Target { get; set; }
    public string? Reason { get; set; }
    public double? Hours { get; set; }
    public bool? Enabled { get; set; }
    public bool? DropMaliciousIps { get; set; }
    public string? ServerUrl { get; set; }
    /// <summary>Bouncer key or device token. Write-only: never returned by the service.</summary>
    public string? ApiKey { get; set; }
    public string? ServerName { get; set; }
    public string? DeviceId { get; set; }
    public string? DohUrl { get; set; }
    /// <summary>Wait for long operations (feed updates) to finish before answering.</summary>
    public bool? Wait { get; set; }
}

public sealed class CoreResponse
{
    public int Id { get; set; }
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public string? Message { get; set; }
    public GuardStatusDto? Status { get; set; }
    public List<GuardDecisionDto>? Decisions { get; set; }
    public List<GuardAlertDto>? Alerts { get; set; }
    public List<string>? Allowlist { get; set; }
}

public sealed class GuardStatusDto
{
    public bool Running { get; set; }
    public string Version { get; set; } = "";
    public DateTimeOffset StartedAt { get; set; }
    public bool Enabled { get; set; }
    public bool UpdatingFeeds { get; set; }
    public DateTimeOffset? LastFeedUpdate { get; set; }
    public DateTimeOffset? LastSync { get; set; }
    /// <summary>Merged addresses/ranges currently enforced (feeds + bans, after the allowlist).</summary>
    public int BlockedEntries { get; set; }
    public long BlockedIPv4Addresses { get; set; }
    public int FirewallRules { get; set; }
    /// <summary>Windows Firewall on for every current profile (null = unknown).</summary>
    public bool? FirewallEnabled { get; set; }
    public int ActiveBans { get; set; }
    public string? LastError { get; set; }
    public List<GuardFeedDto> Feeds { get; set; } = new();
    public List<GuardScenarioDto> Scenarios { get; set; } = new();
    public GuardServerDto Server { get; set; } = new();
    public DnsModeDto Dns { get; set; } = new();
}

public sealed class GuardFeedDto
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string? Homepage { get; set; }
    public bool Enabled { get; set; }
    public bool IsServer { get; set; }
    public DateTimeOffset? LastUpdated { get; set; }
    public int Entries { get; set; }
    public int Skipped { get; set; }
    public string? LastError { get; set; }
}

public sealed class GuardScenarioDto
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public bool Enabled { get; set; }
    public bool Available { get; set; }
    public string? Note { get; set; }
}

public sealed class GuardServerDto
{
    public bool Configured { get; set; }
    public string? Url { get; set; }
    public bool KeySet { get; set; }
    /// <summary>True when the server comes from Account &amp; sync (device token) rather than a manual bouncer key.</summary>
    public bool Linked { get; set; }
    public string? ServerName { get; set; }
    /// <summary>Server policy: Guard managed by the linked server.</summary>
    public bool PolicyManaged { get; set; }
}

public sealed class DnsModeDto
{
    public bool Enabled { get; set; }
    public bool Available { get; set; }
    public string? ServerIp { get; set; }
    public string? DohTemplate { get; set; }
    public string? Note { get; set; }
    public string? LastError { get; set; }
    public int Adapters { get; set; }
}

public sealed class GuardDecisionDto
{
    public string Id { get; set; } = "";
    public string Value { get; set; } = "";
    public string Type { get; set; } = "ban";
    public string Reason { get; set; } = "";
    public string Scenario { get; set; } = "";
    public string Source { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public int Events { get; set; }
}

public sealed class GuardAlertDto
{
    public string Id { get; set; } = "";
    public DateTimeOffset Time { get; set; }
    public string Value { get; set; } = "";
    public string Scenario { get; set; } = "";
    public string Message { get; set; } = "";
    public int Events { get; set; }
    public bool Banned { get; set; }
}

/// <summary>Reads '\n'-terminated UTF-8 messages, keeping any bytes past the newline for the next call.</summary>
public sealed class PipeMessageReader
{
    private readonly Stream _stream;
    private readonly byte[] _buffer = new byte[16 * 1024];
    private int _start, _end;

    public PipeMessageReader(Stream stream) => _stream = stream;

    public async Task<string?> ReadAsync(CancellationToken ct)
    {
        using var acc = new MemoryStream();
        while (true)
        {
            if (_start < _end)
            {
                int nl = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);
                if (nl >= 0)
                {
                    acc.Write(_buffer, _start, nl - _start);
                    _start = nl + 1;
                    return Decode(acc);
                }
                acc.Write(_buffer, _start, _end - _start);
                _start = _end = 0;
                if (acc.Length > CoreIpc.MaxMessageBytes) throw new InvalidDataException("Message too large");
            }
            _start = 0;
            _end = await _stream.ReadAsync(_buffer.AsMemory(), ct).ConfigureAwait(false);
            if (_end == 0) return acc.Length > 0 ? Decode(acc) : null;
        }
    }

    private static string Decode(MemoryStream ms) => Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length).TrimEnd('\r');
}

public static class PipeMessageWriter
{
    public static async Task WriteAsync(Stream stream, string json, CancellationToken ct)
    {
        var bytes = Encoding.UTF8.GetBytes(json + "\n");
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }
}

/// <summary>Client side of the pipe: one connection per request.</summary>
public static class CorePipeClient
{
    private static int _nextId;

    public static async Task<CoreResponse> SendAsync(CoreRequest request, TimeSpan timeout, CancellationToken ct = default,
        string pipeName = CoreIpc.PipeName)
    {
        request.Id = Interlocked.Increment(ref _nextId);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        // Identification only: a process squatting on the pipe name can never impersonate the user.
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(cts.Token).ConfigureAwait(false);
        await PipeMessageWriter.WriteAsync(pipe, JsonSerializer.Serialize(request, CoreIpc.Json), cts.Token).ConfigureAwait(false);
        var line = await new PipeMessageReader(pipe).ReadAsync(cts.Token).ConfigureAwait(false)
                   ?? throw new IOException("ZeroLeakage Core closed the connection without answering");
        return JsonSerializer.Deserialize<CoreResponse>(line, CoreIpc.Json) ?? throw new IOException("Empty answer from ZeroLeakage Core");
    }
}
