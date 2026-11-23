using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ZeroLeakage.Core.Guard;
using ZeroLeakage.Core.Ipc;
using ZeroLeakage.Shared.Ipc;

namespace ZeroLeakage.Core.Tests;

public class IpcTests
{
    private static IpcHandler Handler(TestGuard g) => new(g.Engine, NullLogger<IpcHandler>.Instance);

    private static async Task<CoreResponse> Send(IpcHandler h, CoreRequest req) =>
        JsonSerializer.Deserialize<CoreResponse>(await h.HandleJsonAsync(JsonSerializer.Serialize(req, CoreIpc.Json), default), CoreIpc.Json)!;

    [Fact]
    public async Task Status_ban_unban_allow_round_trip_through_json()
    {
        using var g = new TestGuard();
        var h = Handler(g);

        var status = await Send(h, new CoreRequest { Id = 7, Command = CoreCommands.Status });
        Assert.True(status.Ok);
        Assert.Equal(7, status.Id);
        Assert.True(status.Status!.Running);
        Assert.Equal(6, status.Status.Feeds.Count);
        Assert.Contains(status.Status.Scenarios, s => s.Id == GuardEngine.ScenarioBruteForce);

        var ban = await Send(h, new CoreRequest { Command = CoreCommands.Ban, Value = "45.5.5.5", Reason = "spam", Hours = 2 });
        Assert.True(ban.Ok, ban.Error);
        var list = await Send(h, new CoreRequest { Command = CoreCommands.Decisions });
        var d = Assert.Single(list.Decisions!);
        Assert.Equal("45.5.5.5", d.Value);
        Assert.Equal("spam", d.Reason);
        Assert.Equal(g.Clock.Now.AddHours(2), d.ExpiresAt);

        var bad = await Send(h, new CoreRequest { Command = CoreCommands.Ban, Value = "not-an-ip" });
        Assert.False(bad.Ok);
        Assert.NotNull(bad.Error);

        Assert.True((await Send(h, new CoreRequest { Command = CoreCommands.Unban, Value = "45.5.5.5" })).Ok);
        Assert.True((await Send(h, new CoreRequest { Command = CoreCommands.Allow, Value = "45.6.6.0/24" })).Ok);
        list = await Send(h, new CoreRequest { Command = CoreCommands.Decisions });
        Assert.Empty(list.Decisions!);
        Assert.Equal(new[] { "45.6.6.0/24" }, list.Allowlist);

        Assert.True((await Send(h, new CoreRequest { Command = CoreCommands.SetFeed, Target = "spamhaus-drop", Enabled = true })).Ok);
        Assert.True((await Send(h, new CoreRequest { Command = CoreCommands.SetScenario, Target = GuardEngine.ScenarioPortScan, Enabled = false })).Ok);
        status = await Send(h, new CoreRequest { Command = CoreCommands.Status });
        Assert.True(status.Status!.Feeds.Single(f => f.Id == "spamhaus-drop").Enabled);
        Assert.False(status.Status.Scenarios.Single(s => s.Id == GuardEngine.ScenarioPortScan).Enabled);
    }

    [Fact]
    public async Task Malformed_and_unknown_requests_get_errors_not_exceptions()
    {
        using var g = new TestGuard();
        var h = Handler(g);
        var r1 = JsonSerializer.Deserialize<CoreResponse>(await h.HandleJsonAsync("{not json", default), CoreIpc.Json)!;
        Assert.False(r1.Ok);
        var r2 = await Send(h, new CoreRequest { Command = "formatDisk" });
        Assert.False(r2.Ok);
        Assert.Contains("Unknown command", r2.Error);
        var r3 = await Send(h, new CoreRequest { Command = CoreCommands.SetEnabled });
        Assert.False(r3.Ok);
    }

    [Fact]
    public async Task Update_feeds_and_server_bouncer_use_the_bearer_key_which_is_never_echoed()
    {
        using var g = new TestGuard();
        var h = Handler(g);
        g.Feeds.Texts[FeedCatalog.ServerFeedId] = "45.77.0.1\n45.77.0.2\n";
        var set = await Send(h, new CoreRequest { Command = CoreCommands.SetServer, ServerUrl = "https://zl.example.net", ApiKey = "bouncer-secret-123" });
        Assert.True(set.Ok, set.Error);

        var upd = await Send(h, new CoreRequest { Command = CoreCommands.UpdateFeeds, Wait = true });
        Assert.True(upd.Ok, upd.Error);
        Assert.Contains(g.Feeds.Calls, c => c.Id == FeedCatalog.ServerFeedId && c.Token == "bouncer-secret-123");
        Assert.True(g.Firewall.Blocks("45.77.0.2"));

        var statusJson = await h.HandleJsonAsync(JsonSerializer.Serialize(new CoreRequest { Command = CoreCommands.Status }, CoreIpc.Json), default);
        Assert.DoesNotContain("bouncer-secret-123", statusJson);
        Assert.DoesNotContain("bouncer-secret-123", File.ReadAllText(g.Paths.ConfigFile));   // DPAPI-protected at rest
        var st = JsonSerializer.Deserialize<CoreResponse>(statusJson, CoreIpc.Json)!.Status!;
        Assert.True(st.Server.Configured);
        Assert.True(st.Server.KeySet);
        Assert.Contains(st.Feeds, f => f.IsServer && f.Entries == 2);

        // plain http is only accepted for a private LAN IP
        Assert.False((await Send(h, new CoreRequest { Command = CoreCommands.SetServer, ServerUrl = "http://zl.example.net", ApiKey = "k" })).Ok);
    }

    [Fact]
    public async Task Real_named_pipe_round_trip_with_acl()
    {
        using var g = new TestGuard();
        var pipeName = "ZeroLeakage.Core.Test." + Guid.NewGuid().ToString("N");
        var server = new PipeServer(Handler(g), NullLogger.Instance, pipeName);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await server.StartAsync(cts.Token);
        try
        {
            var r = await CorePipeClient.SendAsync(new CoreRequest { Command = CoreCommands.Status }, TimeSpan.FromSeconds(10), cts.Token, pipeName);
            Assert.True(r.Ok);
            Assert.True(r.Status!.Running);
            // several clients in a row (one connection each) and a second instance while the first is busy
            var many = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ =>
                CorePipeClient.SendAsync(new CoreRequest { Command = CoreCommands.Decisions }, TimeSpan.FromSeconds(10), cts.Token, pipeName)));
            Assert.All(many, m => Assert.True(m.Ok));
        }
        finally
        {
            cts.Cancel();
            try { await server.StopAsync(CancellationToken.None); } catch { }
        }
    }

    [Fact]
    public void Pipe_acl_grants_system_admins_and_interactive_users_only()
    {
        var rules = PipeServer.CreateSecurity().GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<System.IO.Pipes.PipeAccessRule>().ToList();
        var system = rules.Single(r => ((System.Security.Principal.SecurityIdentifier)r.IdentityReference).IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid));
        Assert.Equal(System.IO.Pipes.PipeAccessRights.FullControl, system.PipeAccessRights);
        foreach (var sid in new[] { System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, System.Security.Principal.WellKnownSidType.InteractiveSid })
        {
            var r = rules.Single(x => ((System.Security.Principal.SecurityIdentifier)x.IdentityReference).IsWellKnown(sid));
            Assert.True(r.PipeAccessRights.HasFlag(System.IO.Pipes.PipeAccessRights.ReadWrite));
            Assert.False(r.PipeAccessRights.HasFlag(System.IO.Pipes.PipeAccessRights.CreateNewInstance));
        }
        Assert.DoesNotContain(rules, r => ((System.Security.Principal.SecurityIdentifier)r.IdentityReference).IsWellKnown(System.Security.Principal.WellKnownSidType.WorldSid));
    }
}

public class DnsModeTests
{
    [Fact]
    public async Task Server_dns_saves_previous_settings_then_unlink_restores_them_exactly()
    {
        using var g = new TestGuard();
        var before = g.Dns.Current.ToDictionary(kv => kv.Key, kv => kv.Value);
        Assert.False((await g.Engine.SetDnsModeAsync(true, default)).Ok);   // not linked yet

        Assert.True(g.Engine.SetLink("https://zl.example.net", "device-token", "Home server", "dev1", "https://zl.example.net/dns-query/dev1").Ok);
        var on = await g.Engine.SetDnsModeAsync(true, default);
        Assert.True(on.Ok, on.Error);
        Assert.True(File.Exists(g.Paths.DnsBackupFile));
        Assert.Equal("https://zl.example.net/dns-query/dev1", g.Dns.DohTemplates["203.0.113.50"]);
        Assert.All(g.Dns.Current.Values, v => Assert.Equal("203.0.113.50", v.V4));
        Assert.True(g.Engine.GetStatus().Dns.Enabled);

        // enabling again must not overwrite the original backup with the server's own settings
        Assert.True((await g.Engine.SetDnsModeAsync(true, default)).Ok);

        Assert.True(g.Engine.ClearLink().Ok);
        Assert.Equal(before, g.Dns.Current);
        Assert.Empty(g.Dns.DohTemplates);
        Assert.False(File.Exists(g.Paths.DnsBackupFile));
        Assert.False(g.Engine.GetStatus().Server.Configured);
    }

    [Fact]
    public async Task Toggling_off_restores_and_a_failure_mid_way_rolls_back()
    {
        using var g = new TestGuard();
        var before = g.Dns.Current.ToDictionary(kv => kv.Key, kv => kv.Value);
        g.Engine.SetLink("https://zl.example.net", "t", "Home", null, "https://zl.example.net/dns-query");
        Assert.True((await g.Engine.SetDnsModeAsync(true, default)).Ok);
        Assert.True((await g.Engine.SetDnsModeAsync(false, default)).Ok);
        Assert.Equal(before, g.Dns.Current);

        g.Dns.FailPointing = true;
        var failed = await g.Engine.SetDnsModeAsync(true, default);
        Assert.False(failed.Ok);
        Assert.Equal(before, g.Dns.Current);
        Assert.False(File.Exists(g.Paths.DnsBackupFile));
    }

    [Fact]
    public async Task Unsupported_windows_is_reported_and_changes_nothing()
    {
        using var g = new TestGuard();
        g.Dns.Supported = false;
        g.Engine.SetLink("https://zl.example.net", "t", "Home", null, "https://zl.example.net/dns-query");
        var r = await g.Engine.SetDnsModeAsync(true, default);
        Assert.False(r.Ok);
        Assert.Contains("Windows 11", r.Error);
        Assert.Empty(g.Dns.Log);
    }

    [Fact]
    public async Task Linked_server_policy_manages_guard_and_its_token_feeds_the_bouncer()
    {
        using var g = new TestGuard();
        g.Feeds.Texts[FeedCatalog.ServerFeedId] = "45.88.0.0/24\n";
        Assert.True(g.Engine.SetLink("https://zl.example.net", "device-token-xyz", "Home", "d1", null).Ok);
        await g.Engine.UpdateFeedsAsync(force: true);
        await g.Engine.SyncFirewallAsync();
        Assert.Contains(g.Feeds.Calls, c => c.Id == FeedCatalog.ServerFeedId && c.Token == "device-token-xyz");
        Assert.True(g.Firewall.Blocks("45.88.0.10"));

        Assert.True(g.Engine.SetGuardPolicy(enabled: true, dropMaliciousIps: false).Ok);
        await g.Engine.SyncFirewallAsync();
        Assert.False(g.Firewall.Blocks("45.88.0.10"));
        Assert.False(g.Engine.SetEnabled(false).Ok);                       // the admin's policy wins
        Assert.False(g.Engine.SetServer("https://other.example", "k").Ok);  // linked server can't be swapped here
        Assert.True(g.Engine.GetStatus().Server.PolicyManaged);

        Assert.True(g.Engine.ClearLink().Ok);
        Assert.True(g.Engine.SetEnabled(false).Ok);                        // back in the user's hands
    }
}
