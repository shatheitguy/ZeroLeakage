using System.Net;
using ZeroLeakage.Core.Guard;

namespace ZeroLeakage.Core.Tests;

public class FeedParserTests
{
    [Fact]
    public void Parses_ips_cidrs_ipv6_ranges_and_comments()
    {
        const string text = """
            ; Spamhaus DROP List 2026/11/23
            1.10.16.0/20 ; SBL256894
            # FireHOL style comment
            45.155.205.233
              185.220.101.0/24   # trailing comment
            2a0b:4140:1234::/48
            2001:470:1:2::7
            198.51.99.10-198.51.99.20
            // a C-style comment
            5.188.10.1	extra-column
            """;
        var r = FeedParser.Parse(text);
        Assert.Equal(7, r.Accepted);
        Assert.Equal(0, r.Invalid);
        var set = IpRangeSet.Create(r.Ranges);
        Assert.True(set.Contains(IPAddress.Parse("1.10.31.255")));
        Assert.False(set.Contains(IPAddress.Parse("1.10.32.0")));
        Assert.True(set.Contains(IPAddress.Parse("45.155.205.233")));
        Assert.True(set.Contains(IPAddress.Parse("185.220.101.77")));
        Assert.True(set.Contains(IPAddress.Parse("2a0b:4140:1234:ffff::1")));
        Assert.True(set.Contains(IPAddress.Parse("2001:470:1:2::7")));
        Assert.True(set.Contains(IPAddress.Parse("198.51.99.15")));
        Assert.True(set.Contains(IPAddress.Parse("5.188.10.1")));
    }

    [Fact]
    public void Skips_private_and_reserved_ranges_so_the_lan_is_never_blocked()
    {
        const string text = """
            0.0.0.0/8
            10.0.0.0/8
            10.1.2.3
            127.0.0.1
            169.254.10.10
            172.16.5.5
            192.168.1.0/24
            100.64.1.1
            239.255.255.250
            ::1
            fe80::1
            fd12:3456::1
            ff02::fb
            8.8.4.0/24
            """;
        var r = FeedParser.Parse(text);
        Assert.Equal(13, r.SkippedReserved);
        Assert.Equal(1, r.Accepted);
        Assert.Equal("8.8.4.0/24", Assert.Single(r.Ranges).ToString());
    }

    [Fact]
    public void Rejects_garbage_shorthand_and_overly_broad_entries()
    {
        var r = FeedParser.Parse("<html>\nnot-an-ip\n1.2\n0x7f.1\n999.1.1.1\n1.0.0.0/7\n2000::/3\n1.2.3.4/33\n");
        Assert.Equal(0, r.Accepted);
        Assert.Equal(2, r.TooBroad);
        Assert.Equal(6, r.Invalid);
    }

    [Fact]
    public void Ipv4_mapped_ipv6_is_treated_as_ipv4()
    {
        Assert.True(IpRange.TryParse("::ffff:192.168.1.5", out var lan));
        Assert.Equal(IpFamily.V4, lan.Family);
        Assert.Equal(1, FeedParser.Parse("::ffff:192.168.1.5\n").SkippedReserved);
    }
}

public class IpRangeSetTests
{
    private static IpRangeSet Set(params string[] entries) => IpRangeSet.Parse(entries);

    [Fact]
    public void Merges_overlapping_and_adjacent_ranges()
    {
        var s = Set("1.2.3.0/25", "1.2.3.128/25", "1.2.3.5", "1.2.5.0-1.2.5.9", "1.2.5.10", "9.9.9.9", "2001:db9::1", "2001:db9::2");
        Assert.Equal(new[] { "1.2.3.0/24", "1.2.5.0-1.2.5.10", "9.9.9.9", "2001:db9::1-2001:db9::2" }, s.ToEntries());
    }

    [Fact]
    public void Subtract_punches_holes_and_trims_edges()
    {
        var s = Set("10.0.0.0/8", "20.0.0.0/24", "30.0.0.1").Subtract(Set("10.0.0.0/9", "20.0.0.128/26", "30.0.0.1"));
        Assert.Equal(new[] { "10.128.0.0/9", "20.0.0.0/25", "20.0.0.192/26" }, s.ToEntries());
    }

    [Fact]
    public void Feed_partly_inside_reserved_space_is_trimmed_to_the_public_part()
    {
        var feed = Set("192.167.255.0-192.168.0.255", "172.15.255.255-172.16.0.1");
        var clean = feed.Subtract(ReservedRanges.Set);
        Assert.Equal(new[] { "192.167.255.0/24", "172.15.255.255" }, clean.ToEntries().OrderByDescending(e => e).ToArray());
    }

    [Fact]
    public void Counts_addresses()
    {
        var s = Set("1.0.0.0/24", "2.0.0.1", "2001:db9::/126");
        Assert.Equal((UInt128)257, s.AddressCount(IpFamily.V4));
        Assert.Equal((UInt128)4, s.AddressCount(IpFamily.V6));
    }

    [Fact]
    public void Chunks_never_exceed_1000_entries_and_cover_everything()
    {
        var entries = Enumerable.Range(0, 2500).Select(i => $"45.{i / 250}.{i % 250}.7").ToArray();   // non-adjacent singles
        var set = Set(entries);
        Assert.Equal(2500, set.Count);
        var chunks = GuardFirewallSync.BuildChunks("Feeds", set);
        Assert.Equal(new[] { 1000, 1000, 500 }, chunks.Select(c => c.EntryCount));
        Assert.All(chunks, c => Assert.True(c.Addresses.Split(',').Length <= 1000));
        Assert.Equal(entries.OrderBy(e => e), chunks.SelectMany(c => c.Addresses.Split(',')).OrderBy(e => e));
        Assert.Equal(6, GuardFirewallSync.ToRules(chunks).Count);   // inbound + outbound per chunk
    }

    [Fact]
    public void Netmask_form_from_firewall_readback_parses()
    {
        Assert.True(IpRange.TryParse("1.2.3.0/255.255.255.0", out var r));
        Assert.Equal("1.2.3.0/24", r.ToString());
        Assert.False(IpRange.TryParse("1.2.3.0/255.0.255.0", out _));
    }
}

public class FirewallSyncTests
{
    [Fact]
    public void Diff_update_keeps_unchanged_rules_adds_before_removing()
    {
        var fw = new FakeFirewall();
        var sync = new GuardFirewallSync(fw);
        var chunks1 = GuardFirewallSync.BuildChunks("Feeds", IpRangeSet.Parse(Enumerable.Range(0, 1500).Select(i => $"45.{i / 250}.{i % 250}.9")));
        var bans1 = GuardFirewallSync.BuildChunks("Bans", IpRangeSet.Parse(new[] { "203.0.113.9" }.Concat(new[] { "198.51.99.1" })));
        var first = sync.Apply(chunks1.Concat(bans1).ToList());
        Assert.Equal(6, first.Added);
        Assert.Equal(0, first.Removed);
        Assert.All(fw.Rules.Values, r => Assert.Equal(GuardFirewallSync.Group, r.Group));

        // same feeds, one more ban: only the ban rules are replaced
        fw.Log.Clear();
        var bans2 = GuardFirewallSync.BuildChunks("Bans", IpRangeSet.Parse(new[] { "198.51.99.1", "198.51.99.77" }));
        var second = sync.Apply(chunks1.Concat(bans2).ToList());
        Assert.Equal(2, second.Added);
        Assert.Equal(2, second.Removed);
        Assert.Equal(4, second.Kept);
        int lastAdd = fw.Log.FindLastIndex(l => l.StartsWith("add "));
        int firstRemove = fw.Log.FindIndex(l => l.StartsWith("remove "));
        Assert.True(lastAdd < firstRemove, "all new rules must be in place before any old rule is removed");
        Assert.True(fw.Blocks("198.51.99.77"));
        Assert.True(fw.Blocks("198.51.99.77", FwDirection.Out));

        // identical input: nothing touched
        fw.Log.Clear();
        var third = sync.Apply(chunks1.Concat(bans2).ToList());
        Assert.Equal(0, third.Added + third.Removed);
        Assert.Empty(fw.Log);
    }

    [Fact]
    public void Failed_add_rolls_back_and_keeps_the_previous_rules()
    {
        var fw = new FakeFirewall();
        var sync = new GuardFirewallSync(fw);
        sync.Apply(GuardFirewallSync.BuildChunks("Bans", IpRangeSet.Parse(new[] { "198.51.99.1" })));
        var before = fw.Rules.Keys.ToHashSet();

        int adds = 0;
        fw.FailAdd = _ => ++adds == 2;   // second new rule fails
        Assert.Throws<InvalidOperationException>(() =>
            sync.Apply(GuardFirewallSync.BuildChunks("Bans", IpRangeSet.Parse(new[] { "198.51.99.2" }))));
        Assert.Equal(before, fw.Rules.Keys.ToHashSet());
    }

    [Fact]
    public void Cleanup_removes_only_the_guard_group()
    {
        var fw = new FakeFirewall();
        fw.Rules["Someone else's rule"] = (new FwRuleSpec("Someone else's rule", FwDirection.In, "1.1.1.1", ""), "Other");
        var sync = new GuardFirewallSync(fw);
        sync.Apply(GuardFirewallSync.BuildChunks("Feeds", IpRangeSet.Parse(new[] { "45.1.1.1", "45.1.1.3" })));
        Assert.Equal(2, sync.Cleanup());
        Assert.Equal(new[] { "Someone else's rule" }, fw.Rules.Keys);
    }
}
