using System.Net;

namespace ZeroLeakage.Core.Guard;

/// <summary>An immutable, sorted set of non-overlapping, non-adjacent address ranges (IPv4 first, then IPv6).</summary>
public sealed class IpRangeSet
{
    public static readonly IpRangeSet Empty = new(Array.Empty<IpRange>());

    private readonly IpRange[] _ranges;

    private IpRangeSet(IpRange[] sortedMerged) => _ranges = sortedMerged;

    public IReadOnlyList<IpRange> Ranges => _ranges;
    public int Count => _ranges.Length;
    public bool IsEmpty => _ranges.Length == 0;

    /// <summary>Sorts and merges overlapping or adjacent ranges.</summary>
    public static IpRangeSet Create(IEnumerable<IpRange> ranges)
    {
        var list = ranges.ToList();
        if (list.Count == 0) return Empty;
        list.Sort();
        var merged = new List<IpRange>(list.Count);
        foreach (var r in list)
        {
            if (merged.Count > 0)
            {
                var last = merged[^1];
                if (last.Family == r.Family && (last.End == IpRange.MaxValue(last.Family) || r.Start <= last.End + 1))
                {
                    if (r.End > last.End) merged[^1] = last with { End = r.End };
                    continue;
                }
            }
            merged.Add(r);
        }
        return new IpRangeSet(merged.ToArray());
    }

    public static IpRangeSet Parse(IEnumerable<string> entries) =>
        Create(entries.Select(e => IpRange.TryParse(e, out var r) ? r : (IpRange?)null).OfType<IpRange>());

    public IpRangeSet Union(IpRangeSet other) =>
        other.IsEmpty ? this : IsEmpty ? other : Create(_ranges.Concat(other._ranges));

    /// <summary>Removes every address in <paramref name="other"/> (allowlist precedence).</summary>
    public IpRangeSet Subtract(IpRangeSet other)
    {
        if (IsEmpty || other.IsEmpty) return this;
        var b = other._ranges;
        var result = new List<IpRange>(_ranges.Length);
        int j = 0;
        foreach (var a in _ranges)
        {
            while (j < b.Length && (b[j].Family < a.Family || (b[j].Family == a.Family && b[j].End < a.Start))) j++;
            UInt128 cursor = a.Start;
            bool consumed = false;
            for (int k = j; k < b.Length && b[k].Family == a.Family && b[k].Start <= a.End; k++)
            {
                var x = b[k];
                if (x.End < cursor) continue;
                if (x.Start > cursor) result.Add(new IpRange(a.Family, cursor, x.Start - 1));
                if (x.End >= a.End) { consumed = true; break; }
                cursor = x.End + 1;
            }
            if (!consumed && cursor <= a.End) result.Add(new IpRange(a.Family, cursor, a.End));
        }
        return result.Count == 0 ? Empty : new IpRangeSet(result.ToArray());
    }

    public bool Contains(IPAddress ip) => ContainsRange(IpRange.FromAddress(ip));

    /// <summary>True when every address of <paramref name="r"/> is in the set.</summary>
    public bool ContainsRange(IpRange r)
    {
        int i = FindLastStartingAtOrBefore(r);
        return i >= 0 && _ranges[i].Contains(r);
    }

    public bool Overlaps(IpRange r)
    {
        int i = FindLastStartingAtOrBefore(r);
        if (i >= 0 && _ranges[i].Overlaps(r)) return true;
        return i + 1 < _ranges.Length && _ranges[i + 1].Overlaps(r);
    }

    private int FindLastStartingAtOrBefore(IpRange r)
    {
        int lo = 0, hi = _ranges.Length - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var m = _ranges[mid];
            bool before = m.Family < r.Family || (m.Family == r.Family && m.Start <= r.Start);
            if (before) { found = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return found;
    }

    /// <summary>Total addresses of one family (saturating).</summary>
    public UInt128 AddressCount(IpFamily family)
    {
        UInt128 total = 0;
        foreach (var r in _ranges)
        {
            if (r.Family != family) continue;
            var s = r.Size;
            total = UInt128.MaxValue - total < s ? UInt128.MaxValue : total + s;
        }
        return total;
    }

    /// <summary>Firewall RemoteAddresses entries, one per range.</summary>
    public IEnumerable<string> ToEntries() => _ranges.Select(r => r.ToString());
}
