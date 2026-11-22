using System;
using System.Collections.Generic;
using System.Linq;

namespace ZeroLeakage.UI.Services.Dns;

public enum RuleKind { BlockExact, BlockSuffix, AllowExact, AllowSuffix }

public readonly record struct ParsedRule(RuleKind Kind, string Domain);

/// <summary>Why a lookup was blocked / allowed by the filter lists.</summary>
public sealed record FilterMatch(bool Blocked, string ListId, string ListName, string Category, string Rule, string Matched);

/// <summary>
/// AdGuard-Home-style DNS rule parser: hosts files, plain domain lists, <c>||domain^</c> and <c>@@||domain^</c>.
/// Rules a DNS filter can't express (paths, regex, wildcards, cosmetic, $dnstype…) are skipped.
/// Mirrors the Android implementation.
/// </summary>
public static class FilterParser
{
    private static readonly HashSet<string> HostIps = new() { "0.0.0.0", "127.0.0.1", "::", "::0", "::1", "0", "0:0:0:0:0:0:0:0" };
    private static readonly HashSet<string> SkipHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
    };
    private static readonly HashSet<string> OkModifiers = new() { "important", "third-party", "3p", "all", "document", "doc" };

    public static ParsedRule? ParseLine(string raw, bool plainIsSuffix = false)
    {
        var line = raw.Trim();
        if (line.Length == 0) return null;
        char c = line[0];
        if (c is '!' or '#' or '[') return null;
        if (line.Contains("##") || line.Contains("#@#") || line.Contains("#?#") || line.Contains("#$#")) return null;

        bool allow = false;
        if (line.StartsWith("@@", StringComparison.Ordinal)) { allow = true; line = line[2..]; }

        if (line.StartsWith("||", StringComparison.Ordinal))
        {
            var body = line[2..];
            int caret = body.IndexOf('^');
            string domainPart, rest;
            if (caret >= 0) { domainPart = body[..caret]; rest = body[(caret + 1)..]; }
            else
            {
                int dollar = body.IndexOf('$');
                domainPart = dollar >= 0 ? body[..dollar] : body.TrimEnd('|');
                rest = dollar >= 0 ? body[dollar..] : "";
            }
            if (rest.StartsWith('|')) rest = rest[1..];
            if (rest.Length > 0)
            {
                if (rest[0] != '$') return null;
                if (rest[1..].Split(',').Any(m => !OkModifiers.Contains(m.Trim().ToLowerInvariant()))) return null;
            }
            var d = CleanDomain(domainPart);
            return d is null ? null : new ParsedRule(allow ? RuleKind.AllowSuffix : RuleKind.BlockSuffix, d);
        }
        if (allow)
        {
            var d = CleanDomain(line.TrimEnd('^', '|'));
            return d is null ? null : new ParsedRule(RuleKind.AllowSuffix, d);
        }
        if (line[0] is '|' or '/' || line.Contains('$') || line.Contains('*')) return null;

        int hash = line.IndexOf('#');
        if (hash >= 0) line = line[..hash].Trim();
        if (line.Length == 0) return null;
        var tokens = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        string host;
        if (tokens.Length >= 2 && HostIps.Contains(tokens[0])) host = tokens[1];
        else if (tokens.Length == 1) host = tokens[0];
        else return null;
        if (SkipHosts.Contains(host)) return null;
        var dom = CleanDomain(host);
        return dom is null ? null : new ParsedRule(plainIsSuffix ? RuleKind.BlockSuffix : RuleKind.BlockExact, dom);
    }

    public static string? CleanDomain(string raw)
    {
        var d = raw.Trim().TrimEnd('.').ToLowerInvariant();
        if (d.Length is < 3 or > 253 || !d.Contains('.')) return null;
        if (d[0] is '.' or '-') return null;
        foreach (var ch in d)
            if (!(ch is >= 'a' and <= 'z' || ch is >= '0' and <= '9' || ch is '.' or '-' or '_')) return null;
        if (d.Contains("..")) return null;
        if (d.All(ch => char.IsDigit(ch) || ch == '.')) return null;
        return d;
    }

    public static string? Normalize(string raw)
    {
        var d = raw.Trim().ToLowerInvariant();
        if (d.StartsWith("http://")) d = d[7..];
        if (d.StartsWith("https://")) d = d[8..];
        if (d.StartsWith("||")) d = d[2..];
        d = d.Split('^')[0].Split('/')[0].Split(':')[0];
        return CleanDomain(d);
    }
}

/// <summary>Immutable index over every enabled list; duplicates stored once (first list wins).</summary>
public sealed class FilterIndex
{
    public sealed record Label(string Id, string Name, string Category);

    private readonly List<Label> _labels;
    private readonly Dictionary<string, short> _blockExact, _blockSuffix, _allowExact, _allowSuffix;
    private readonly HashSet<string> _userAllow, _userBlock;

    public IReadOnlyDictionary<string, int> Counts { get; }
    public int TotalRules => _blockExact.Count + _blockSuffix.Count + _allowExact.Count + _allowSuffix.Count;

    private FilterIndex(List<Label> labels, Dictionary<string, short> be, Dictionary<string, short> bs, Dictionary<string, short> ae,
                        Dictionary<string, short> asf, HashSet<string> userAllow, HashSet<string> userBlock, Dictionary<string, int> counts)
    {
        _labels = labels; _blockExact = be; _blockSuffix = bs; _allowExact = ae; _allowSuffix = asf;
        _userAllow = userAllow; _userBlock = userBlock; Counts = counts;
    }

    public static readonly FilterIndex Empty = new Builder().Build();

    public FilterIndex WithUser(IEnumerable<string> allow, IEnumerable<string> block) =>
        new(_labels, _blockExact, _blockSuffix, _allowExact, _allowSuffix, new HashSet<string>(allow), new HashSet<string>(block), (Dictionary<string, int>)Counts);

    public FilterMatch? Match(string domain)
    {
        var d = domain.ToLowerInvariant().TrimEnd('.');
        foreach (var s in Walk(d)) if (_userAllow.Contains(s)) return new(false, "user_allow", "Your allowlist", "Allowlisted", $"@@||{s}^", s);
        foreach (var s in Walk(d)) if (_userBlock.Contains(s)) return new(true, "user_block", "Your blocklist", "User Blocklist", $"||{s}^", s);
        if (_allowExact.TryGetValue(d, out var i)) return Hit(false, i, $"@@|{d}^", d);
        foreach (var s in Walk(d)) if (_allowSuffix.TryGetValue(s, out i)) return Hit(false, i, $"@@||{s}^", s);
        if (_blockExact.TryGetValue(d, out i)) return Hit(true, i, $"0.0.0.0 {d}", d);
        foreach (var s in Walk(d)) if (_blockSuffix.TryGetValue(s, out i)) return Hit(true, i, $"||{s}^", s);
        return null;
    }

    private static IEnumerable<string> Walk(string domain)
    {
        var d = domain;
        while (true)
        {
            yield return d;
            int dot = d.IndexOf('.');
            if (dot < 0 || dot == d.Length - 1) yield break;
            d = d[(dot + 1)..];
            if (!d.Contains('.')) yield break;
        }
    }

    private FilterMatch Hit(bool blocked, short idx, string rule, string matched)
    {
        var l = _labels[idx];
        return new FilterMatch(blocked, l.Id, l.Name, l.Category, rule, matched);
    }

    public sealed class Builder
    {
        private readonly List<Label> _labels = new();
        private readonly Dictionary<string, short> _be = new(), _bs = new(), _ae = new(), _as = new();
        private readonly Dictionary<string, int> _counts = new();
        private HashSet<string> _userAllow = new(), _userBlock = new();

        public int AddList(Label label, IEnumerable<string> lines, bool plainIsSuffix = false)
        {
            if (_labels.Count >= short.MaxValue) return 0;
            var idx = (short)_labels.Count;
            _labels.Add(label);
            int n = 0;
            foreach (var line in lines)
            {
                if (FilterParser.ParseLine(line, plainIsSuffix) is not { } r) continue;
                n++;
                var map = r.Kind switch { RuleKind.BlockExact => _be, RuleKind.BlockSuffix => _bs, RuleKind.AllowExact => _ae, _ => _as };
                map.TryAdd(r.Domain, idx);
            }
            _counts[label.Id] = n;
            return n;
        }

        public Builder User(IEnumerable<string> allow, IEnumerable<string> block)
        {
            _userAllow = new HashSet<string>(allow);
            _userBlock = new HashSet<string>(block);
            return this;
        }

        public FilterIndex Build() => new(_labels, _be, _bs, _ae, _as, _userAllow, _userBlock, _counts);
    }
}
