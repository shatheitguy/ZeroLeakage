using ZeroLeakage.Shared.Link;

namespace ZeroLeakage.Core.Tests;

public class LinkSyncTests
{
    private const string Server = "https://zl.example.net";

    private sealed class Rig
    {
        public readonly FakeServer Srv;
        public readonly FakeTarget Target = new();
        public readonly FakeCore Core = new();
        public readonly MemoryLinkStore Store = new();
        public readonly ManualClock Clock = new();
        public readonly SyncService Sync;

        public Rig(FakeServer? server = null)
        {
            Srv = server ?? new FakeServer();
            Sync = new SyncService(new ServerApiClient(new HttpClient(Srv)), Store, Target, Core, Clock, () => "DESKTOP-TEST")
            {
                DebounceDelay = TimeSpan.FromHours(1),   // tests sync explicitly
            };
        }
    }

    [Fact]
    public async Task Pairing_code_link_clones_the_server_exactly()
    {
        var rig = new Rig();
        var r = await rig.Sync.LinkWithCodeAsync("zl.example.net", "zl abcd 2345");   // sloppy input is normalised
        Assert.True(r.Ok, r.Error);
        Assert.Null(r.Error);

        var st = rig.Sync.State!;
        Assert.Equal("Home server", st.ServerName);
        Assert.Equal("DESKTOP-TEST", st.DeviceName);
        Assert.Equal("alice", st.Username);
        Assert.Equal("7", st.PolicyVersion);
        Assert.NotNull(st.LastSync);

        // exact clone: only the server's lists (admin baseline), its rules (none yet) and no local leftovers
        Assert.Equal(new[] { "adguard_dns" }, rig.Target.Enabled.OrderBy(x => x));
        Assert.Empty(rig.Target.Custom);
        Assert.Empty(rig.Target.Allow);
        Assert.Empty(rig.Target.Block);
        Assert.Equal(new[] { "casino.example", "tiktok.com", "tiktokv.com" }, rig.Target.ManagedBlock);
        Assert.Contains("adguard_dns", rig.Target.Locked);
        Assert.Equal("Home server", rig.Target.ManagedBy);

        // nothing local was uploaded on link, and the Core service got the device token + guard policy
        Assert.DoesNotContain(rig.Srv.Requests, q => q.Method == "PUT");
        Assert.Equal(st.Token, rig.Core.Link!.Token);
        Assert.Contains("guard True True", rig.Core.Calls);
        Assert.Equal("https://zl.example.net/dns-query/dev-alice", rig.Core.Link.DohUrl);
    }

    [Fact]
    public async Task Wrong_code_and_insecure_addresses_are_rejected()
    {
        var rig = new Rig();
        Assert.Contains("wrong or has expired", (await rig.Sync.LinkWithCodeAsync(Server, "ZL-0000-0000")).Error);
        Assert.False((await rig.Sync.LinkWithCodeAsync(Server, "12")).Ok);
        Assert.Contains("https", (await rig.Sync.LinkWithCodeAsync("http://zl.example.net", "ZL-ABCD-2345")).Error);
        Assert.False(rig.Sync.IsLinked);
        Assert.Null(rig.Store.Json);

        // http to a private LAN IP is allowed, with a warning
        Assert.True(ServerAddress.TryNormalize("http://192.168.1.10:8080/", out var lan, out var err, out var warn));
        Assert.Null(err);
        Assert.NotNull(warn);
        Assert.Equal("http://192.168.1.10:8080/", lan!.AbsoluteUri);
    }

    [Fact]
    public async Task Username_and_password_sign_in_links_and_never_stores_the_password()
    {
        var rig = new Rig();
        Assert.Contains("Wrong username or password", (await rig.Sync.SignInAsync(Server, "alice", "nope")).Error);
        var r = await rig.Sync.SignInAsync(Server, "alice", "correct horse");
        Assert.True(r.Ok, r.Error);
        Assert.Equal("alice", rig.Sync.State!.Username);

        var login = rig.Srv.Requests.Last(q => q.Path == "/api/v1/devices/link");
        Assert.Contains("\"platform\":\"windows\"", login.Body);
        Assert.Contains("\"deviceName\":\"DESKTOP-TEST\"", login.Body);
        Assert.DoesNotContain("correct horse", rig.Store.Json);
        Assert.Contains(rig.Sync.State.Token, rig.Store.Json);                 // only the token is kept…
        Assert.All(rig.Srv.Requests.Where(q => q.Path == "/api/v1/sync"), q => Assert.Equal(rig.Sync.State.Token, q.Auth));
    }

    [Fact]
    public async Task Two_way_rule_merge_last_writer_wins()
    {
        var rig = new Rig();
        Assert.True((await rig.Sync.LinkWithCodeAsync(Server, "ZL-ABCD-2345")).Ok);

        // another of alice's devices blocks a domain on the server
        rig.Srv.User("alice").Rules["block|ads.example"] = new SyncRule { Kind = "block", Domain = "ads.example", UpdatedAt = rig.Clock.Now.ToUnixTimeMilliseconds() - 5000 };

        // locally: alice allows news.example and blocks tracker.example
        rig.Clock.Advance(TimeSpan.FromSeconds(10));
        rig.Target.Allow.Add("news.example");
        rig.Target.Block.Add("tracker.example");
        var o = await rig.Sync.SyncNowAsync();
        Assert.True(o.Ok, o.Error);
        Assert.Equal(2, o.RulesPushed);
        Assert.Equal(new[] { "ads.example", "tracker.example" }, rig.Target.Block.OrderBy(x => x));
        Assert.Equal(new[] { "news.example" }, rig.Target.Allow);

        // local edit moves ads.example from block to allow (newer than the server's record) → allow wins everywhere
        rig.Clock.Advance(TimeSpan.FromSeconds(10));
        rig.Target.Block.Remove("ads.example");
        rig.Target.Allow.Add("ads.example");
        Assert.True((await rig.Sync.SyncNowAsync()).Ok);
        Assert.True(rig.Srv.User("alice").Rules["block|ads.example"].Deleted);
        Assert.False(rig.Srv.User("alice").Rules["allow|ads.example"].Deleted);
        Assert.Contains("ads.example", rig.Target.Allow);
        Assert.DoesNotContain("ads.example", rig.Target.Block);

        // an older edit from a slow device loses
        rig.Srv.User("alice").Rules["block|ads.example"] = new SyncRule { Kind = "block", Domain = "ads.example", UpdatedAt = 1 };
        Assert.True((await rig.Sync.SyncNowAsync()).Ok);
        Assert.Contains("ads.example", rig.Target.Allow);
        Assert.DoesNotContain("ads.example", rig.Target.Block);

        // a newer server-side delete removes the local rule
        rig.Srv.User("alice").Rules["block|tracker.example"] = new SyncRule
            { Kind = "block", Domain = "tracker.example", UpdatedAt = rig.Clock.Now.ToUnixTimeMilliseconds() + 60_000, Deleted = true };
        Assert.True((await rig.Sync.SyncNowAsync()).Ok);
        Assert.DoesNotContain("tracker.example", rig.Target.Block);
    }

    [Fact]
    public async Task Locked_items_cannot_be_disabled_or_unblocked()
    {
        var rig = new Rig();
        Assert.True((await rig.Sync.LinkWithCodeAsync(Server, "ZL-ABCD-2345")).Ok);
        var locks = rig.Sync.Locks;
        Assert.True(locks.IsListLocked("adguard_dns"));
        Assert.True(locks.IsServiceLocked("tiktok"));

        // the UI refuses an allow rule for anything under the admin's blocked domains, with a clear message
        var reason = rig.Target.TryUserAllow(locks, "www.casino.example");
        Assert.NotNull(reason);
        Assert.Contains("Set by admin", reason);
        Assert.Contains("casino.example", reason);
        Assert.Null(rig.Target.TryUserAllow(locks, "fine.example"));

        // even if a locked list is switched off behind the UI's back, the next sync turns it back on and doesn't push it as a user change
        rig.Target.Enabled.Remove("adguard_dns");
        rig.Target.Allow.Add("casino.example");          // and a smuggled allow for a locked domain is never applied or uploaded
        var o = await rig.Sync.SyncNowAsync();
        Assert.True(o.Ok, o.Error);
        Assert.Contains("adguard_dns", rig.Target.Enabled);
        Assert.DoesNotContain("casino.example", rig.Target.Allow);
        Assert.Contains("casino.example", rig.Target.ManagedBlock);
        Assert.DoesNotContain(rig.Srv.User("alice").Rules.Keys, k => k.Contains("casino.example"));

        // an admin-locked service can't be removed; the user's own can
        Assert.Contains("Set by admin", await rig.Sync.SetUserServiceAsync("tiktok", blocked: false));
        Assert.Null(await rig.Sync.SetUserServiceAsync("youtube", blocked: true));
        Assert.True((await rig.Sync.SyncNowAsync()).Ok);
        Assert.Contains("youtube.com", rig.Target.ManagedBlock);
        Assert.Null(await rig.Sync.SetUserServiceAsync("youtube", blocked: false));
        Assert.True((await rig.Sync.SyncNowAsync()).Ok);
        Assert.DoesNotContain("youtube.com", rig.Target.ManagedBlock);
        Assert.Contains("tiktok.com", rig.Target.ManagedBlock);

        // the admin's lock also overrides an allow rule the user already had on the server
        rig.Srv.User("alice").Rules["allow|bet.example"] = new SyncRule { Kind = "allow", Domain = "bet.example", UpdatedAt = 5 };
        rig.Srv.Locked.BlockDomains!.Add("bet.example");
        Assert.True((await rig.Sync.SyncNowAsync()).Ok);
        Assert.DoesNotContain("bet.example", rig.Target.Allow);
        Assert.Contains("bet.example", rig.Target.LastPlan!.RejectedAllows);
        Assert.False(rig.Srv.User("alice").Rules["allow|bet.example"].Deleted);   // left alone on the server
    }

    [Fact]
    public async Task User_extras_round_trip_between_the_same_users_apps_only()
    {
        var srv = new FakeServer();
        srv.Codes["ZL-WXYZ-6789"] = "alice";
        srv.Codes["ZL-BOBB-0001"] = "bob";
        var laptop = new Rig(srv);
        var desktop = new Rig(srv);
        var bobs = new Rig(srv);
        Assert.True((await laptop.Sync.LinkWithCodeAsync(Server, "ZL-ABCD-2345")).Ok);
        Assert.True((await desktop.Sync.LinkWithCodeAsync(Server, "ZL-WXYZ-6789")).Ok);
        Assert.True((await bobs.Sync.LinkWithCodeAsync(Server, "ZL-BOBB-0001")).Ok);

        // alice adds an extra list, a custom list and a rule on her laptop
        laptop.Clock.Advance(TimeSpan.FromMinutes(1));
        laptop.Target.Enabled.Add("hagezi_pro");
        laptop.Target.Custom.Add(new CustomListSpec { Url = "https://lists.example/extra.txt", Name = "Extra" });
        laptop.Target.Block.Add("social.example");
        var push = await laptop.Sync.SyncNowAsync();
        Assert.True(push.Ok, push.Error);
        Assert.True(push.UserPolicyPushed);
        Assert.Equal(new[] { "hagezi_pro" }, srv.LastPush!.UserPolicy!.Lists);                     // admin's locked list isn't sent as a user extra
        Assert.Equal("https://lists.example/extra.txt", Assert.Single(srv.LastPush.UserPolicy.CustomLists).Url);

        // her desktop picks it all up; bob's PC doesn't
        Assert.True((await desktop.Sync.SyncNowAsync()).Ok);
        Assert.Equal(new[] { "adguard_dns", "hagezi_pro" }, desktop.Target.Enabled.OrderBy(x => x));
        var custom = Assert.Single(desktop.Target.Custom);
        Assert.Equal("https://lists.example/extra.txt", custom.Url);
        Assert.False(custom.Locked);
        Assert.Contains("social.example", desktop.Target.Block);

        Assert.True((await bobs.Sync.SyncNowAsync()).Ok);
        Assert.Equal(new[] { "adguard_dns" }, bobs.Target.Enabled);
        Assert.Empty(bobs.Target.Custom);
        Assert.DoesNotContain("social.example", bobs.Target.Block);

        // and back: the desktop drops the extra list, the laptop follows
        desktop.Clock.Advance(TimeSpan.FromMinutes(2));
        desktop.Target.Enabled.Remove("hagezi_pro");
        Assert.True((await desktop.Sync.SyncNowAsync()).Ok);
        Assert.True((await laptop.Sync.SyncNowAsync()).Ok);
        Assert.Equal(new[] { "adguard_dns" }, laptop.Target.Enabled);
        Assert.Single(laptop.Target.Custom);
    }

    [Fact]
    public async Task Unlink_restores_the_pre_link_protection_and_tells_core()
    {
        var rig = new Rig();
        var before = await rig.Target.SnapshotAsync();
        Assert.True((await rig.Sync.LinkWithCodeAsync(Server, "ZL-ABCD-2345")).Ok);
        Assert.NotEqual(before.EnabledLists.OrderBy(x => x), rig.Target.Enabled.OrderBy(x => x));
        Assert.Null(await rig.Sync.SetUseServerDnsAsync(true));
        Assert.Contains("dns True", rig.Core.Calls);

        await rig.Sync.UnlinkAsync();
        Assert.False(rig.Sync.IsLinked);
        Assert.Null(rig.Store.Json);
        Assert.Contains("clear", rig.Core.Calls);                       // Core restores Windows DNS and drops the token
        Assert.Equal(before.EnabledLists.OrderBy(x => x), rig.Target.Enabled.OrderBy(x => x));
        Assert.Equal(before.Allow, rig.Target.Allow);
        Assert.Equal(before.Block, rig.Target.Block);
        Assert.Equal(before.CustomLists.Select(c => c.Url), rig.Target.Custom.Select(c => c.Url));
        Assert.Empty(rig.Target.ManagedBlock);
        Assert.Empty(rig.Target.Locked);
    }

    [Fact]
    public async Task Revoked_token_is_reported_and_server_dns_needs_core()
    {
        var rig = new Rig();
        Assert.True((await rig.Sync.LinkWithCodeAsync(Server, "ZL-ABCD-2345")).Ok);
        rig.Srv.Tokens.Clear();
        var o = await rig.Sync.SyncNowAsync();
        Assert.False(o.Ok);
        Assert.True(rig.Sync.State!.Revoked);
        Assert.Contains("no longer authorized", rig.Sync.State.LastError);

        rig.Core.Running = false;
        Assert.NotNull(await rig.Sync.SetUseServerDnsAsync(true));
        Assert.False(rig.Sync.State.UseServerDns);
    }

    [Fact]
    public void Dpapi_store_round_trips_and_keeps_the_token_encrypted_at_rest()
    {
        var path = Path.Combine(Path.GetTempPath(), "zl-link-tests", Guid.NewGuid().ToString("N"), "link.dat");
        try
        {
            var store = new DpapiLinkStore(path);
            Assert.Null(store.Load());
            store.Save(new LinkState { ServerUrl = Server, Token = "super-secret-device-token", ServerName = "Home" });
            Assert.DoesNotContain("super-secret-device-token", File.ReadAllText(path));
            Assert.Equal("super-secret-device-token", store.Load()!.Token);
            File.WriteAllBytes(path, new byte[] { 1, 2, 3 });
            Assert.Null(store.Load());                                   // damaged / another user's file = not linked
            store.Delete();
            Assert.False(File.Exists(path));
        }
        finally { try { Directory.Delete(Path.GetDirectoryName(path)!, true); } catch { } }
    }

    [Fact]
    public void Pairing_code_and_domain_normalisation()
    {
        Assert.Equal("ZL-ABCD-2345", PairingCode.Normalize(" zl-abcd-2345 "));
        Assert.Equal("ZL-ABCD-2345", PairingCode.Normalize("ABCD2345"));
        Assert.Null(PairingCode.Normalize("ZL-ABC-2345"));
        Assert.Equal("ads.example", DomainName.Normalize("||Ads.Example^"));
        Assert.Null(DomainName.Normalize("localhost"));
        Assert.True(DomainName.IsSameOrSubdomain("a.b.casino.example", "casino.example"));
        Assert.False(DomainName.IsSameOrSubdomain("notcasino.example", "casino.example"));
    }
}
