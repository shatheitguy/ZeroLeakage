namespace ZeroLeakage.Core.Guard;

/// <summary>Address space Guard must never block, whatever a feed says: the LAN, loopback, link-local, multicast…</summary>
public static class ReservedRanges
{
    public static readonly IReadOnlyList<string> Cidrs = new[]
    {
        // IPv4 special-purpose (RFC 6890 and friends)
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        // IPv6 (IPv4-mapped addresses are normalised to IPv4 before they get here)
        "::/128", "::1/128", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
    };

    public static readonly IpRangeSet Set = IpRangeSet.Parse(Cidrs);
}

public sealed record FeedParseResult(IReadOnlyList<IpRange> Ranges, int Accepted, int SkippedReserved, int Invalid, int TooBroad);

/// <summary>Parses plain-text threat lists: one IP, CIDR or range per line; '#', ';' and '//' comments.</summary>
public static class FeedParser
{
    /// <summary>Safety floor: a feed may never block more than a /8 (IPv4) or /20 (IPv6) in one entry.</summary>
    public const int MinPrefixV4 = 8;
    public const int MinPrefixV6 = 20;

    public static FeedParseResult Parse(string text, IpRangeSet? reserved = null)
    {
        reserved ??= ReservedRanges.Set;
        var ranges = new List<IpRange>();
        int accepted = 0, skipped = 0, invalid = 0, broad = 0;
        foreach (var rawLine in text.AsSpan().EnumerateLines())
        {
            var line = rawLine.Trim();
            if (line.IsEmpty || line.StartsWith("//")) continue;
            int comment = line.IndexOfAny('#', ';');
            if (comment >= 0) line = line[..comment].Trim();
            if (line.IsEmpty) continue;
            int ws = line.IndexOfAny(" \t,");
            if (ws > 0) line = line[..ws];

            if (!IpRange.TryParse(line.ToString(), out var r)) { invalid++; continue; }
            if (IsTooBroad(r)) { broad++; continue; }
            if (reserved.ContainsRange(r)) { skipped++; continue; }
            ranges.Add(r);
            accepted++;
        }
        return new FeedParseResult(ranges, accepted, skipped, invalid, broad);
    }

    public static bool IsTooBroad(IpRange r)
    {
        int bits = IpRange.Bits(r.Family);
        int min = r.Family == IpFamily.V4 ? MinPrefixV4 : MinPrefixV6;
        return r.Size > (UInt128.One << (bits - min));
    }
}
