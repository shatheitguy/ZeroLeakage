namespace ZeroLeakage.Shared.Link;

/// <summary>Pure sync logic: rule merging (last writer wins), the clone plan, and journaling local edits.</summary>
public static class SyncPlanner
{
    public const string Allow = "allow";
    public const string Block = "block";

    public static string Key(SyncRule r) => r.Kind + "|" + r.Domain;

    /// <summary>Lower-cases the kind, normalises the domain; null for anything unusable.</summary>
    public static SyncRule? Normalize(SyncRule? r)
    {
        if (r is null) return null;
        var kind = r.Kind?.Trim().ToLowerInvariant();
        if (kind is not (Allow or Block)) return null;
        var d = DomainName.Normalize(r.Domain);
        return d is null ? null : new SyncRule { Kind = kind, Domain = d, UpdatedAt = r.UpdatedAt, Deleted = r.Deleted };
    }

    /// <summary>Per (kind, domain) keeps the newest record. On a tie the later sequence wins (local edits over server copy).</summary>
    public static Dictionary<string, SyncRule> Merge(params IEnumerable<SyncRule>[] sources)
    {
        var map = new Dictionary<string, SyncRule>(StringComparer.Ordinal);
        foreach (var src in sources)
        foreach (var raw in src)
        {
            var r = Normalize(raw);
            if (r is null) continue;
            if (!map.TryGetValue(Key(r), out var cur) || r.UpdatedAt >= cur.UpdatedAt) map[Key(r)] = r;
        }
        return map;
    }

    /// <summary>Final allow/block domains. A domain that is live as both kinds goes to the newest one.</summary>
    public static (List<string> Allow, List<string> Block) Resolve(IEnumerable<SyncRule> rules)
    {
        var winner = new Dictionary<string, SyncRule>(StringComparer.Ordinal);
        foreach (var r in rules)
        {
            if (r.Deleted) continue;
            if (!winner.TryGetValue(r.Domain, out var cur) || r.UpdatedAt > cur.UpdatedAt) winner[r.Domain] = r;
        }
        var allow = winner.Values.Where(r => r.Kind == Allow).Select(r => r.Domain).OrderBy(d => d, StringComparer.Ordinal).ToList();
        var block = winner.Values.Where(r => r.Kind == Block).Select(r => r.Domain).OrderBy(d => d, StringComparer.Ordinal).ToList();
        return (allow, block);
    }

    /// <summary>The rules as the app currently applies them (newest record per key, admin-locked allows dropped).</summary>
    public static (List<string> Allow, List<string> Block) AppliedView(IEnumerable<SyncRule> known, IEnumerable<SyncRule> pending, PolicyLocks locks)
    {
        var (allow, block) = Resolve(Merge(known, pending).Values);
        allow.RemoveAll(d => locks.BlocksDomain(d, out _));
        return (allow, block);
    }

    /// <summary>Journals local edits: anything added or removed compared with what sync last applied, stamped <paramref name="nowMs"/>.</summary>
    public static List<SyncRule> Diff((List<string> Allow, List<string> Block) applied, IEnumerable<string> localAllow,
        IEnumerable<string> localBlock, long nowMs)
    {
        var changes = new List<SyncRule>();
        void Compare(string kind, IEnumerable<string> before, IEnumerable<string> now)
        {
            var b = new HashSet<string>(before, StringComparer.Ordinal);
            var n = new HashSet<string>(now.Select(DomainName.Normalize).OfType<string>(), StringComparer.Ordinal);
            foreach (var d in n.Where(d => !b.Contains(d)).OrderBy(d => d, StringComparer.Ordinal))
                changes.Add(new SyncRule { Kind = kind, Domain = d, UpdatedAt = nowMs });
            foreach (var d in b.Where(d => !n.Contains(d)).OrderBy(d => d, StringComparer.Ordinal))
                changes.Add(new SyncRule { Kind = kind, Domain = d, UpdatedAt = nowMs, Deleted = true });
        }
        Compare(Allow, applied.Allow, localAllow);
        Compare(Block, applied.Block, localBlock);
        return changes;
    }

    /// <summary>
    /// The admin's baseline. Servers that send "locked" get exactly that; an older server without it is treated
    /// as fully managed (its whole policy is read-only in the app).
    /// </summary>
    public static PolicyLocks BuildLocks(LockedPolicy? locked, SyncPolicy? policy, string managedBy)
    {
        if (locked is not null)
            return new PolicyLocks(locked.Lists ?? new(), locked.Services ?? new(), locked.Categories ?? new(),
                locked.BlockDomains ?? new(), managedBy);
        if (policy is not null)
            return new PolicyLocks(policy.Lists ?? new(), policy.Services ?? new(), policy.Categories ?? new(), Array.Empty<string>(), managedBy);
        return PolicyLocks.None;
    }

    public static SyncPlan BuildPlan(SyncResponse server, IEnumerable<SyncRule> rules, UserPolicy user,
        IReadOnlyCollection<string> catalogIds, string managedBy)
    {
        var policy = server.Policy ?? new SyncPolicy();
        var locks = BuildLocks(server.Locked, server.Policy, managedBy);
        var catalog = new HashSet<string>(catalogIds, StringComparer.OrdinalIgnoreCase);
        var plan = new SyncPlan { ManagedBy = managedBy, Locks = locks, BypassBlocking = policy.BypassBlocking };

        // Filter lists: admin baseline + the user's extras (+ whatever the server reports as effective).
        var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in (policy.Lists ?? new()).Concat(locks.Lists).Concat(user.Lists)) wanted.Add(id.Trim());
        foreach (var id in wanted.OrderBy(i => i, StringComparer.OrdinalIgnoreCase))
        {
            if (catalog.Contains(id)) plan.EnabledLists.Add(id);
            else if (id.Length > 0 && !IsCustomId(id, policy, user)) plan.UnknownLists.Add(id);
        }
        foreach (var id in locks.Lists) if (catalog.Contains(id)) plan.LockedLists.Add(id);

        // Custom lists by URL: the user's own are editable, anything else the server sends is the admin's.
        var userUrls = new HashSet<string>(user.CustomLists.Select(c => c.Url ?? "").Where(u => u.Length > 0), StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in (policy.CustomLists ?? new()).Concat(user.CustomLists))
        {
            if (string.IsNullOrWhiteSpace(c.Url) || !IsHttpUrl(c.Url) || !seen.Add(c.Url.Trim())) continue;
            plan.CustomLists.Add(new CustomListSpec
            {
                Url = c.Url.Trim(),
                Name = string.IsNullOrWhiteSpace(c.Name) ? new Uri(c.Url.Trim()).Host : c.Name.Trim(),
                Category = string.IsNullOrWhiteSpace(c.Category) ? "Custom List" : c.Category.Trim(),
                Enabled = true,
                Locked = !userUrls.Contains(c.Url.Trim()),
            });
        }

        // The user's own allow/block rules; the admin's blocks always win over a user allow.
        var (allow, block) = Resolve(rules);
        plan.RejectedAllows = allow.Where(d => locks.BlocksDomain(d, out _)).ToList();
        plan.Allow = allow.Except(plan.RejectedAllows, StringComparer.Ordinal).ToList();
        plan.Block = block;

        plan.LockedBlockDomains = locks.BlockDomains.OrderBy(d => d, StringComparer.Ordinal).ToList();
        var userBlock = new HashSet<string>(plan.Block, StringComparer.Ordinal);
        var userAllow = new HashSet<string>(plan.Allow, StringComparer.Ordinal);
        plan.ManagedBlock = (server.Effective?.Block ?? new()).Concat(plan.LockedBlockDomains)
            .Select(DomainName.Normalize).OfType<string>()
            .Where(d => !userBlock.Contains(d)).Distinct(StringComparer.Ordinal).OrderBy(d => d, StringComparer.Ordinal).ToList();
        plan.ManagedAllow = (server.Effective?.Allow ?? new())
            .Select(DomainName.Normalize).OfType<string>()
            .Where(d => !userAllow.Contains(d) && !locks.BlocksDomain(d, out _))
            .Distinct(StringComparer.Ordinal).OrderBy(d => d, StringComparer.Ordinal).ToList();
        return plan;
    }

    /// <summary>The user's extras as the app currently has them: enabled lists and custom lists that aren't the admin's.</summary>
    public static UserPolicy UserPolicyFromLocal(LocalProtectionSnapshot local, PolicyLocks locks, SyncPolicy? policy, UserPolicy previous)
    {
        var adminCustom = new HashSet<string>((policy?.CustomLists ?? new()).Select(c => c.Url?.Trim() ?? ""), StringComparer.OrdinalIgnoreCase);
        foreach (var c in previous.CustomLists) adminCustom.Remove(c.Url?.Trim() ?? "");
        var prevCustom = previous.CustomLists.Where(c => c.Url is not null)
            .GroupBy(c => c.Url!.Trim(), StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        return new UserPolicy
        {
            Lists = local.EnabledLists.Where(id => !locks.IsListLocked(id)).Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(i => i, StringComparer.OrdinalIgnoreCase).ToList(),
            CustomLists = local.CustomLists
                .Where(c => c.Enabled && !c.Locked && !adminCustom.Contains(c.Url.Trim()))
                .Select(c => new CustomListDto
                {
                    Id = prevCustom.TryGetValue(c.Url.Trim(), out var p) ? p.Id : null,
                    Name = c.Name, Url = c.Url.Trim(), Category = c.Category,
                }).ToList(),
            Services = previous.Services.ToList(),
            Categories = previous.Categories.ToList(),
            SafeSearch = previous.SafeSearch?.Clone(),
        };
    }

    public static bool SameUserPolicy(UserPolicy a, UserPolicy b)
    {
        static bool SameSet(IEnumerable<string?> x, IEnumerable<string?> y) =>
            new HashSet<string>(x.OfType<string>(), StringComparer.OrdinalIgnoreCase).SetEquals(y.OfType<string>());
        return SameSet(a.Lists, b.Lists)
            && SameSet(a.CustomLists.Select(c => c.Url?.Trim()), b.CustomLists.Select(c => c.Url?.Trim()))
            && SameSet(a.Services, b.Services)
            && SameSet(a.Categories, b.Categories)
            && (a.SafeSearch?.GetRawText() ?? "") == (b.SafeSearch?.GetRawText() ?? "");
    }

    private static bool IsCustomId(string id, SyncPolicy policy, UserPolicy user) =>
        (policy.CustomLists ?? new()).Concat(user.CustomLists).Any(c => string.Equals(c.Id, id, StringComparison.OrdinalIgnoreCase));

    private static bool IsHttpUrl(string url) =>
        Uri.TryCreate(url.Trim(), UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || u.Scheme == Uri.UriSchemeHttp);
}
