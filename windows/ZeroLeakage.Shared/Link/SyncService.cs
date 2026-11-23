namespace ZeroLeakage.Shared.Link;

public sealed record LinkResult(bool Ok, string? Error = null, string? Warning = null);

public sealed record SyncOutcome(bool Ok, string? Error = null, int RulesPushed = 0, bool UserPolicyPushed = false);

/// <summary>
/// Keeps the desktop app an exact clone of the user's protection on a ZeroLeakage Server:
/// push local edits (rules last-writer-wins, the user's own extras), pull, then apply the admin baseline + user extras.
/// Runs on start, every 30 minutes, and 3 seconds after a local edit.
/// </summary>
public sealed class SyncService : IDisposable
{
    private readonly ServerApiClient _api;
    private readonly ILinkStore _store;
    private readonly ISyncTarget _target;
    private readonly ICoreBridge _core;
    private readonly TimeProvider _clock;
    private readonly Func<string> _deviceName;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private LinkState? _state;
    private ITimer? _periodic, _debounce;
    private bool _syncing, _disposed;

    public SyncService(ServerApiClient api, ILinkStore store, ISyncTarget target, ICoreBridge core, TimeProvider? clock = null,
        Func<string>? deviceName = null)
    {
        _api = api;
        _store = store;
        _target = target;
        _core = core;
        _clock = clock ?? TimeProvider.System;
        _deviceName = deviceName ?? (() => Environment.MachineName);
        _state = _store.Load();
    }

    public TimeSpan DebounceDelay { get; init; } = TimeSpan.FromSeconds(3);
    public TimeSpan Interval { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>Raised (on a worker thread) whenever link or sync state changes.</summary>
    public event EventHandler? Changed;

    public bool IsLinked => _state is not null;
    public bool IsSyncing => _syncing;
    /// <summary>A copy-free view of the current link. Never show <see cref="LinkState.Token"/>.</summary>
    public LinkState? State => _state;
    public PolicyLocks Locks => _state is { } s ? SyncPlanner.BuildLocks(s.Locked, s.Policy, s.ServerName) : PolicyLocks.None;

    /// <summary>Starts the 30-minute schedule and, when linked, an immediate sync.</summary>
    public void Start()
    {
        _periodic?.Dispose();
        _periodic = _clock.CreateTimer(_ => { if (IsLinked) _ = SyncNowAsync(); }, null, TimeSpan.FromSeconds(2), Interval);
    }

    public async Task<LinkResult> LinkWithCodeAsync(string serverAddress, string code, CancellationToken ct = default)
    {
        if (!ServerAddress.TryNormalize(serverAddress, out var server, out var err, out var warn)) return new(false, err);
        var normalized = PairingCode.Normalize(code);
        if (normalized is null) return new(false, "Pairing codes look like ZL-XXXX-XXXX");
        return await LinkAsync(server!, warn, null, c => _api.PairAsync(server!, normalized, _deviceName(), c), ct).ConfigureAwait(false);
    }

    /// <summary>Signs in with username + password. The password is sent once and never stored.</summary>
    public async Task<LinkResult> SignInAsync(string serverAddress, string username, string password, CancellationToken ct = default)
    {
        if (!ServerAddress.TryNormalize(serverAddress, out var server, out var err, out var warn)) return new(false, err);
        var user = username?.Trim() ?? "";
        if (user.Length == 0 || string.IsNullOrEmpty(password)) return new(false, "Enter your username and password");
        return await LinkAsync(server!, warn, user, c => _api.SignInAsync(server!, user, password, _deviceName(), c), ct).ConfigureAwait(false);
    }

    private async Task<LinkResult> LinkAsync(Uri server, string? warning, string? username, Func<CancellationToken, Task<LinkResponse>> call,
        CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        SyncOutcome first;
        try
        {
            if (_state is not null) return new(false, "This PC is already linked. Unlink it first.");
            LinkResponse resp;
            try { resp = await call(ct).ConfigureAwait(false); }
            catch (ServerApiException ex) { return new(false, ex.Message, warning); }

            var backup = await _target.SnapshotAsync().ConfigureAwait(false);
            _state = new LinkState
            {
                ServerUrl = server.AbsoluteUri.TrimEnd('/'),
                Token = resp.Token!,
                DeviceId = resp.Device?.Id,
                DeviceName = string.IsNullOrWhiteSpace(resp.Device?.Name) ? _deviceName() : resp.Device!.Name!,
                Username = resp.User?.Username ?? (string.IsNullOrWhiteSpace(resp.Username) ? username : resp.Username),
                ServerName = FirstNonEmpty(resp.Server?.Name, resp.Server?.Hostname, server.Host),
                ServerVersion = resp.Server?.Version,
                ServerHostname = resp.Server?.Hostname,
                DohUrl = resp.Device?.DohUrl,
                DotHost = resp.Device?.DotHost,
                LinkedAt = _clock.GetUtcNow(),
                PreLinkBackup = backup,
            };
            _store.Save(_state);
            await _core.SetLinkAsync(LinkInfo(_state), ct).ConfigureAwait(false);
            first = await SyncCoreAsync(ct).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
        RaiseChanged();
        return first.Ok ? new(true, null, warning) : new(true, "Linked, but the first sync failed: " + first.Error, warning);
    }

    public async Task<SyncOutcome> SyncNowAsync(CancellationToken ct = default)
    {
        if (_disposed) return new(false, "Stopped");
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        SyncOutcome result;
        try { result = await SyncCoreAsync(ct).ConfigureAwait(false); }
        finally { _gate.Release(); }
        RaiseChanged();
        return result;
    }

    private async Task<SyncOutcome> SyncCoreAsync(CancellationToken ct)
    {
        var st = _state;
        if (st is null) return new(false, "Not linked");
        _syncing = true;
        RaiseChanged();
        int pushedRules = 0;
        bool pushedPolicy = false;
        try
        {
            var server = new Uri(st.ServerUrl);

            // 1) local edits first (never on the very first sync: the server's state replaces the PC's)
            if (st.InitialSyncDone)
            {
                await JournalLocalAsync(st).ConfigureAwait(false);
                if (st.PendingRules.Count > 0 || st.PendingUserPolicy is not null)
                {
                    var push = new SyncPush
                    {
                        Rules = st.PendingRules.Select(r => r.Clone()).ToList(),
                        UserPolicy = st.PendingUserPolicy?.Clone(),
                    };
                    await _api.PutSyncAsync(server, st.Token, push, ct).ConfigureAwait(false);
                    st.KnownRules = SyncPlanner.Merge(st.KnownRules, push.Rules).Values.ToList();
                    st.PendingRules.RemoveAll(r => push.Rules.Any(p => SyncPlanner.Key(p) == SyncPlanner.Key(r) && p.UpdatedAt >= r.UpdatedAt));
                    if (push.UserPolicy is not null)
                    {
                        st.UserPolicy = push.UserPolicy;
                        st.PendingUserPolicy = null;
                    }
                    pushedRules = push.Rules.Count;
                    pushedPolicy = push.UserPolicy is not null;
                    _store.Save(st);
                }
            }

            // 2) pull and apply the clone
            var s = await _api.GetSyncAsync(server, st.Token, ct).ConfigureAwait(false);
            st.KnownRules = (s.Rules ?? new()).Select(SyncPlanner.Normalize).OfType<SyncRule>().ToList();
            if (s.UserPolicy is not null) st.UserPolicy = s.UserPolicy;
            st.Policy = s.Policy;
            st.Locked = s.Locked;
            st.PolicyVersion = s.PolicyVersion ?? st.PolicyVersion;
            st.DohUrl = s.DohUrl ?? st.DohUrl;
            st.DotHost = s.DotHost ?? st.DotHost;
            st.DeviceId = s.DeviceId ?? st.DeviceId;
            if (!string.IsNullOrWhiteSpace(s.User?.Username)) st.Username = s.User!.Username;

            var merged = SyncPlanner.Merge(st.KnownRules, st.PendingRules).Values;
            var user = st.PendingUserPolicy ?? st.UserPolicy ?? new UserPolicy();
            var plan = SyncPlanner.BuildPlan(s, merged, user, _target.CatalogListIds, st.ServerName);
            await _target.ApplyAsync(plan, ct).ConfigureAwait(false);

            // 3) the Core service: Guard bouncer source + the server's Guard policy (best effort; it may not be installed)
            await _core.SetLinkAsync(LinkInfo(st), ct).ConfigureAwait(false);
            if (s.Policy?.Guard is { } g) await _core.SetGuardPolicyAsync(g.Enabled, g.DropMaliciousIps, ct).ConfigureAwait(false);

            st.InitialSyncDone = true;
            st.LastSync = _clock.GetUtcNow();
            st.LastError = null;
            st.Revoked = false;
            _store.Save(st);
            return new(true, null, pushedRules, pushedPolicy);
        }
        catch (ServerApiException ex)
        {
            st.LastError = ex.Message;
            st.Revoked = ex.IsUnauthorized;
            _store.Save(st);
            return new(false, ex.Message, pushedRules, pushedPolicy);
        }
        finally { _syncing = false; }
    }

    /// <summary>Records what the user changed locally since the last apply (rules + their own extras).</summary>
    private async Task JournalLocalAsync(LinkState st)
    {
        var local = await _target.SnapshotAsync().ConfigureAwait(false);
        var locks = SyncPlanner.BuildLocks(st.Locked, st.Policy, st.ServerName);
        var applied = SyncPlanner.AppliedView(st.KnownRules, st.PendingRules, locks);
        var now = _clock.GetUtcNow().ToUnixTimeMilliseconds();
        foreach (var change in SyncPlanner.Diff(applied, local.Allow.Where(d => locks.CanAllow(d, out _)), local.Block, now))
        {
            st.PendingRules.RemoveAll(r => SyncPlanner.Key(r) == SyncPlanner.Key(change));
            st.PendingRules.Add(change);
        }
        var current = st.PendingUserPolicy ?? st.UserPolicy ?? new UserPolicy();
        var fromLocal = SyncPlanner.UserPolicyFromLocal(local, locks, st.Policy, current);
        if (!SyncPlanner.SameUserPolicy(fromLocal, current)) st.PendingUserPolicy = fromLocal;
    }

    /// <summary>Call after any local rule or list change; syncs 3 seconds after the last one.</summary>
    public void NotifyLocalChange()
    {
        if (!IsLinked || _disposed) return;
        _debounce?.Dispose();
        _debounce = _clock.CreateTimer(_ => _ = SyncNowAsync(), null, DebounceDelay, Timeout.InfiniteTimeSpan);
    }

    /// <summary>Adds or removes one of the user's own blocked services (admin-set ones can't be removed).</summary>
    public async Task<string?> SetUserServiceAsync(string serviceId, bool blocked)
    {
        var id = serviceId?.Trim().ToLowerInvariant() ?? "";
        if (id.Length is 0 or > 64 || !id.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.'))
            return "Service ids are short names like youtube or tiktok";
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_state is not { } st) return "Not linked";
            var locks = SyncPlanner.BuildLocks(st.Locked, st.Policy, st.ServerName);
            if (!blocked && locks.IsServiceLocked(id)) return $"Set by admin: {id} stays blocked on your network.";
            var p = (st.PendingUserPolicy ?? st.UserPolicy ?? new UserPolicy()).Clone();
            p.Services.RemoveAll(s => s.Equals(id, StringComparison.OrdinalIgnoreCase));
            if (blocked) p.Services.Add(id);
            st.PendingUserPolicy = p;
            _store.Save(st);
        }
        finally { _gate.Release(); }
        NotifyLocalChange();
        RaiseChanged();
        return null;
    }

    public async Task<string?> SetUseServerDnsAsync(bool on, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_state is not { } st) return "Link this PC to a server first";
            if (on && string.IsNullOrWhiteSpace(st.DohUrl)) return "Your server didn't send a DNS-over-HTTPS address for this device";
            if (on && !await _core.SetLinkAsync(LinkInfo(st), ct).ConfigureAwait(false))
                return "The ZeroLeakage Core service isn't running, so Windows DNS can't be changed";
            var (ok, error) = await _core.SetDnsModeAsync(on, ct).ConfigureAwait(false);
            if (!ok) return error ?? "The ZeroLeakage Core service couldn't change Windows DNS";
            st.UseServerDns = on;
            _store.Save(st);
        }
        finally { _gate.Release(); }
        RaiseChanged();
        return null;
    }

    /// <summary>Forgets the server: the Core service drops the link (and restores DNS), and the pre-link protection comes back.</summary>
    public async Task UnlinkAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_state is not { } st) return;
            _debounce?.Dispose();
            await _core.ClearLinkAsync(ct).ConfigureAwait(false);
            await _target.RestoreAsync(st.PreLinkBackup ?? await _target.SnapshotAsync().ConfigureAwait(false), ct).ConfigureAwait(false);
            _store.Delete();
            _state = null;
        }
        finally { _gate.Release(); }
        RaiseChanged();
    }

    private static CoreLinkInfo LinkInfo(LinkState st) => new(new Uri(st.ServerUrl), st.Token, st.ServerName, st.DeviceId, st.DohUrl);

    private static string FirstNonEmpty(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim() ?? "";

    private void RaiseChanged()
    {
        try { Changed?.Invoke(this, EventArgs.Empty); }
        catch { /* a UI handler must never break sync */ }
    }

    public void Dispose()
    {
        _disposed = true;
        _periodic?.Dispose();
        _debounce?.Dispose();
    }
}

/// <summary>Talks to the Core service over the named pipe. Every call is best effort: false when the service isn't there.</summary>
public sealed class PipeCoreBridge : ICoreBridge
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(4);
    private readonly Func<bool> _isServiceRunning;

    public PipeCoreBridge(Func<bool> isServiceRunning) => _isServiceRunning = isServiceRunning;

    public Task<bool> SetLinkAsync(CoreLinkInfo info, CancellationToken ct) => SendAsync(new Ipc.CoreRequest
    {
        Command = Ipc.CoreCommands.SetLink,
        ServerUrl = info.Server.AbsoluteUri.TrimEnd('/'),
        ApiKey = info.Token,
        ServerName = info.ServerName,
        DeviceId = info.DeviceId,
        DohUrl = info.DohUrl,
    }, ct);

    public Task<bool> ClearLinkAsync(CancellationToken ct) => SendAsync(new Ipc.CoreRequest { Command = Ipc.CoreCommands.ClearLink }, ct);

    public Task<bool> SetGuardPolicyAsync(bool enabled, bool dropMaliciousIps, CancellationToken ct) =>
        SendAsync(new Ipc.CoreRequest { Command = Ipc.CoreCommands.SetGuardPolicy, Enabled = enabled, DropMaliciousIps = dropMaliciousIps }, ct);

    public async Task<(bool Ok, string? Error)> SetDnsModeAsync(bool enabled, CancellationToken ct)
    {
        if (!_isServiceRunning()) return (false, "The ZeroLeakage Core service isn't running");
        try
        {
            var r = await Ipc.CorePipeClient.SendAsync(new Ipc.CoreRequest { Command = Ipc.CoreCommands.SetDnsMode, Enabled = enabled },
                TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
            return (r.Ok, r.Error);
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            return (false, "The ZeroLeakage Core service didn't answer");
        }
    }

    private async Task<bool> SendAsync(Ipc.CoreRequest req, CancellationToken ct)
    {
        if (!_isServiceRunning()) return false;
        try { return (await Ipc.CorePipeClient.SendAsync(req, Timeout, ct).ConfigureAwait(false)).Ok; }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            return false;
        }
    }
}
