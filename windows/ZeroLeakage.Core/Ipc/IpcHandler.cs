using System.Text.Json;
using Microsoft.Extensions.Logging;
using ZeroLeakage.Core.Guard;
using ZeroLeakage.Shared.Ipc;

namespace ZeroLeakage.Core.Ipc;

/// <summary>Turns pipe messages into Guard engine calls. Never echoes secrets back.</summary>
public sealed class IpcHandler
{
    private readonly GuardEngine _engine;
    private readonly ILogger _log;

    public IpcHandler(GuardEngine engine, ILogger<IpcHandler> log)
    {
        _engine = engine;
        _log = log;
    }

    public async Task<string> HandleJsonAsync(string json, CancellationToken ct)
    {
        CoreRequest? req;
        try { req = JsonSerializer.Deserialize<CoreRequest>(json, CoreIpc.Json); }
        catch (JsonException) { req = null; }
        var resp = req is null
            ? new CoreResponse { Ok = false, Error = "Malformed request" }
            : await HandleAsync(req, ct).ConfigureAwait(false);
        return JsonSerializer.Serialize(resp, CoreIpc.Json);
    }

    public async Task<CoreResponse> HandleAsync(CoreRequest req, CancellationToken ct)
    {
        try
        {
            switch (req.Command)
            {
                case CoreCommands.Status:
                    return Ok(req, s => s.Status = _engine.GetStatus());

                case CoreCommands.Decisions:
                    return Ok(req, s =>
                    {
                        s.Decisions = _engine.GetDecisions();
                        s.Alerts = _engine.GetAlerts();
                        s.Allowlist = _engine.GetAllowlist();
                    });

                case CoreCommands.Ban: return From(req, _engine.Ban(req.Value, req.Reason, req.Hours));
                case CoreCommands.Unban: return From(req, _engine.Unban(req.Value));
                case CoreCommands.Allow: return From(req, _engine.Allow(req.Value));
                case CoreCommands.RemoveAllow: return From(req, _engine.RemoveAllow(req.Value));

                case CoreCommands.SetEnabled:
                    return req.Enabled is { } on ? From(req, _engine.SetEnabled(on)) : Error(req, "Missing 'enabled'");
                case CoreCommands.SetFeed:
                    return req.Enabled is { } fon && req.Target is { } feed ? From(req, _engine.SetFeedEnabled(feed, fon)) : Error(req, "Missing feed or 'enabled'");
                case CoreCommands.SetScenario:
                    return req.Enabled is { } son && req.Target is { } sc ? From(req, _engine.SetScenarioEnabled(sc, son)) : Error(req, "Missing scenario or 'enabled'");

                case CoreCommands.UpdateFeeds:
                    if (req.Wait == true)
                    {
                        var r = await _engine.UpdateFeedsAsync(force: true, ct).ConfigureAwait(false);
                        await _engine.SyncFirewallAsync(ct).ConfigureAwait(false);
                        return From(req, r);
                    }
                    if (_engine.IsUpdatingFeeds) return Ok(req, s => s.Message = "Already updating");
                    _ = _engine.StartFeedUpdate(force: true);
                    return Ok(req, s => s.Message = "Updating threat feeds…");

                case CoreCommands.SetServer: return From(req, _engine.SetServer(req.ServerUrl, req.ApiKey));
                case CoreCommands.SetLink: return From(req, _engine.SetLink(req.ServerUrl, req.ApiKey, req.ServerName, req.DeviceId, req.DohUrl));
                case CoreCommands.ClearLink: return From(req, _engine.ClearLink());
                case CoreCommands.SetGuardPolicy:
                    return req.Enabled is { } gon ? From(req, _engine.SetGuardPolicy(gon, req.DropMaliciousIps ?? true)) : Error(req, "Missing 'enabled'");
                case CoreCommands.SetDnsMode:
                    return req.Enabled is { } don ? From(req, await _engine.SetDnsModeAsync(don, ct).ConfigureAwait(false)) : Error(req, "Missing 'enabled'");

                default:
                    return Error(req, $"Unknown command '{Truncate(req.Command)}'");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "IPC command {Command} failed", Truncate(req.Command));
            return Error(req, "ZeroLeakage Core hit an internal error: " + ex.Message);
        }
    }

    private static CoreResponse Ok(CoreRequest req, Action<CoreResponse> fill)
    {
        var r = new CoreResponse { Id = req.Id, Ok = true };
        fill(r);
        return r;
    }

    private static CoreResponse From(CoreRequest req, OpResult op) =>
        new() { Id = req.Id, Ok = op.Ok, Error = op.Error, Message = op.Message };

    private static CoreResponse Error(CoreRequest req, string error) => new() { Id = req.Id, Ok = false, Error = error };

    private static string Truncate(string? s) => s is null ? "" : s.Length <= 40 ? s : s[..40];
}
