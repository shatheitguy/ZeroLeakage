using System.Net;
using ZeroLeakage.Core.Guard;

namespace ZeroLeakage.Core.Tests;

public class BruteForceTests
{
    [Fact]
    public void Fires_at_threshold_within_the_window_only()
    {
        var d = new BruteForceDetector(5, TimeSpan.FromMinutes(10));
        var ip = IPAddress.Parse("45.9.9.9");
        var t = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        for (int i = 0; i < 4; i++) Assert.Null(d.Record(ip, t.AddMinutes(i)));
        var hit = d.Record(ip, t.AddMinutes(4));
        Assert.NotNull(hit);
        Assert.Equal(5, hit!.Events);
        Assert.Equal(0, d.TrackedIps);   // bucket emptied after firing
    }

    [Fact]
    public void Slow_attempts_spread_beyond_the_window_never_fire()
    {
        var d = new BruteForceDetector(5, TimeSpan.FromMinutes(10));
        var ip = IPAddress.Parse("45.9.9.9");
        var t = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        for (int i = 0; i < 20; i++) Assert.Null(d.Record(ip, t.AddMinutes(i * 3)));   // 4 per 10 minutes at most
    }

    [Fact]
    public void Different_sources_are_counted_separately()
    {
        var d = new BruteForceDetector(3, TimeSpan.FromMinutes(10));
        var t = DateTimeOffset.UnixEpoch;
        Assert.Null(d.Record(IPAddress.Parse("45.1.1.1"), t));
        Assert.Null(d.Record(IPAddress.Parse("45.1.1.2"), t));
        Assert.Null(d.Record(IPAddress.Parse("45.1.1.1"), t));
        Assert.NotNull(d.Record(IPAddress.Parse("45.1.1.1"), t));
    }

    [Fact]
    public async Task Engine_bans_brute_forcer_then_expires_the_ban()
    {
        using var g = new TestGuard();
        for (int i = 0; i < 4; i++) g.Engine.OnFailedLogon("45.66.77.88", "Administrator");
        Assert.Empty(g.Engine.GetDecisions());
        g.Engine.OnFailedLogon("::ffff:45.66.77.88", "Administrator");   // mapped form counts for the same IP

        var ban = Assert.Single(g.Engine.GetDecisions());
        Assert.Equal("45.66.77.88", ban.Value);
        Assert.Equal(GuardEngine.ScenarioBruteForce, ban.Scenario);
        Assert.Equal(g.Clock.Now.AddHours(4), ban.ExpiresAt);
        var alert = Assert.Single(g.Engine.GetAlerts());
        Assert.True(alert.Banned);

        await g.Engine.SyncFirewallAsync();
        Assert.True(g.Firewall.Blocks("45.66.77.88"));
        Assert.True(g.Firewall.Blocks("45.66.77.88", FwDirection.Out));

        g.Clock.Advance(TimeSpan.FromHours(3.9));
        Assert.Equal(0, g.Engine.ExpireDecisions());
        g.Clock.Advance(TimeSpan.FromHours(0.2));
        Assert.Equal(1, g.Engine.ExpireDecisions());
        Assert.Empty(g.Engine.GetDecisions());
        await g.Engine.SyncFirewallAsync();
        Assert.False(g.Firewall.Blocks("45.66.77.88"));
        Assert.Empty(g.Firewall.Rules);
    }

    [Fact]
    public void Ignores_missing_source_and_disabled_scenario()
    {
        using var g = new TestGuard();
        for (int i = 0; i < 10; i++) g.Engine.OnFailedLogon("-", "x");
        Assert.Empty(g.Engine.GetAlerts());
        Assert.True(g.Engine.SetScenarioEnabled(GuardEngine.ScenarioBruteForce, false).Ok);
        for (int i = 0; i < 10; i++) g.Engine.OnFailedLogon("45.1.2.3", "x");
        Assert.Empty(g.Engine.GetDecisions());
    }

    [Fact]
    public void Port_scan_needs_many_distinct_ports()
    {
        using var g = new TestGuard();
        for (int i = 0; i < 40; i++) g.Engine.OnDroppedInbound("45.10.10.10", 445);   // one port hammered: not a scan
        Assert.Empty(g.Engine.GetDecisions());
        for (int p = 1; p <= 15; p++) g.Engine.OnDroppedInbound("45.10.10.11", 1000 + p);
        Assert.Equal(GuardEngine.ScenarioPortScan, Assert.Single(g.Engine.GetDecisions()).Scenario);
        for (int p = 1; p <= 30; p++) g.Engine.OnDroppedInbound("192.168.1.50", p);   // LAN chatter ignored
        Assert.Single(g.Engine.GetDecisions());
    }

    [Fact]
    public void Firewall_log_parser_reads_dropped_inbound_packets()
    {
        var p = new FirewallLogParser();
        Assert.Null(p.ParseLine("#Version: 1.5"));
        Assert.Null(p.ParseLine("#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid"));
        var e = p.ParseLine("2026-11-23 10:00:01 DROP TCP 45.1.2.3 192.168.1.20 51515 3389 52 S 1234 0 64240 - - - RECEIVE 4");
        Assert.NotNull(e);
        Assert.True(FirewallLogParser.IsDroppedInbound(e!));
        Assert.Equal("45.1.2.3", e!.SourceIp);
        Assert.Equal(3389, e.DestinationPort);
        Assert.False(FirewallLogParser.IsDroppedInbound(p.ParseLine("2026-11-23 10:00:01 ALLOW TCP 45.1.2.3 192.168.1.20 51515 443 52 - - - - - - - SEND 4")!));
    }
}

public class AllowlistTests
{
    [Fact]
    public async Task Allowlist_beats_feeds_and_bans()
    {
        using var g = new TestGuard();
        g.Feeds.Texts["feodo"] = "45.20.0.0/24\n45.30.0.5\n";
        Assert.True(g.Engine.SetFeedEnabled("feodo", true).Ok);
        await g.Engine.UpdateFeedsAsync(force: true);
        await g.Engine.SyncFirewallAsync();
        Assert.True(g.Firewall.Blocks("45.20.0.77"));

        Assert.True(g.Engine.Allow("45.20.0.77").Ok);
        await g.Engine.SyncFirewallAsync();
        Assert.False(g.Firewall.Blocks("45.20.0.77"));
        Assert.True(g.Firewall.Blocks("45.20.0.76"));
        Assert.True(g.Firewall.Blocks("45.20.0.78"));

        // a manual ban of an allowlisted address is refused
        var refused = g.Engine.Ban("45.20.0.77", "test", null);
        Assert.False(refused.Ok);
        Assert.Contains("allowlist", refused.Error);

        // removing the allow entry restores the feed's block
        Assert.True(g.Engine.RemoveAllow("45.20.0.77").Ok);
        await g.Engine.SyncFirewallAsync();
        Assert.True(g.Firewall.Blocks("45.20.0.77"));
    }

    [Fact]
    public async Task Never_bans_lan_this_pc_or_gateway_even_when_attacked()
    {
        using var g = new TestGuard();
        for (int i = 0; i < 5; i++) g.Engine.OnFailedLogon("192.168.1.1", "admin");    // the gateway
        for (int i = 0; i < 5; i++) g.Engine.OnFailedLogon("10.0.0.99", "admin");      // RFC 1918
        Assert.Empty(g.Engine.GetDecisions());
        Assert.Equal(2, g.Engine.GetAlerts().Count);
        Assert.All(g.Engine.GetAlerts(), a => Assert.False(a.Banned));
        Assert.False(g.Engine.Ban("192.168.0.0/16", null, null).Ok);
        Assert.False(g.Engine.Ban("127.0.0.1", null, null).Ok);

        // this PC's public address (e.g. a VPS NIC) is protected too
        g.Network.Addresses.Add(IPAddress.Parse("45.99.99.99"));
        Assert.False(g.Engine.Ban("45.99.99.99", null, null).Ok);
        Assert.True(g.Engine.Ban("45.99.99.0/24", "range", null).Ok);   // partial overlap allowed, the PC is carved out
        await g.Engine.SyncFirewallAsync();
        Assert.False(g.Firewall.Blocks("45.99.99.99"));
        Assert.True(g.Firewall.Blocks("45.99.99.98"));
    }

    [Fact]
    public async Task Allowing_an_ip_lifts_its_ban_and_disable_removes_all_rules()
    {
        using var g = new TestGuard();
        Assert.True(g.Engine.Ban("45.1.1.1", "x", 2).Ok);
        Assert.True(g.Engine.Allow("45.1.1.0/24").Ok);
        Assert.Empty(g.Engine.GetDecisions());

        Assert.True(g.Engine.Ban("45.2.2.2", "x", null).Ok);
        await g.Engine.SyncFirewallAsync();
        Assert.NotEmpty(g.Firewall.Rules);
        Assert.True(g.Engine.SetEnabled(false).Ok);
        await g.Engine.SyncFirewallAsync();
        Assert.Empty(g.Firewall.Rules);
    }

    [Fact]
    public async Task State_persists_across_restarts()
    {
        using var g = new TestGuard();
        g.Engine.Ban("45.3.3.3", "keep me", null);
        g.Engine.Allow("45.4.4.4");
        var again = new GuardEngine(g.Paths, g.Firewall, g.Feeds, g.Network, g.Dns, g.Clock,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<GuardEngine>.Instance);
        again.Initialize();
        Assert.Equal("45.3.3.3", Assert.Single(again.GetDecisions()).Value);
        Assert.Contains("45.4.4.4", again.GetAllowlist());
        await again.SyncFirewallAsync();
        Assert.True(g.Firewall.Blocks("45.3.3.3"));
    }
}
