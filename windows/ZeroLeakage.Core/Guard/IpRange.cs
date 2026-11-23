using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ZeroLeakage.Core.Guard;

public enum IpFamily : byte { V4 = 4, V6 = 6 }

/// <summary>An inclusive range of IPv4 or IPv6 addresses, both stored as 128-bit integers.</summary>
public readonly record struct IpRange(IpFamily Family, UInt128 Start, UInt128 End) : IComparable<IpRange>
{
    public static UInt128 MaxValue(IpFamily family) => family == IpFamily.V4 ? uint.MaxValue : UInt128.MaxValue;
    public static int Bits(IpFamily family) => family == IpFamily.V4 ? 32 : 128;

    public bool IsSingle => Start == End;

    /// <summary>Number of addresses (saturates at UInt128.MaxValue for ::/0).</summary>
    public UInt128 Size => End - Start == UInt128.MaxValue ? UInt128.MaxValue : End - Start + 1;

    public int CompareTo(IpRange other)
    {
        int c = Family.CompareTo(other.Family);
        if (c != 0) return c;
        c = Start.CompareTo(other.Start);
        return c != 0 ? c : End.CompareTo(other.End);
    }

    public bool Contains(IpRange other) => Family == other.Family && Start <= other.Start && End >= other.End;
    public bool Overlaps(IpRange other) => Family == other.Family && Start <= other.End && other.Start <= End;

    public static IpRange FromAddress(IPAddress ip)
    {
        var (f, v) = ToValue(ip);
        return new IpRange(f, v, v);
    }

    public static IpRange FromCidr(IPAddress network, int prefix)
    {
        var (f, v) = ToValue(network);
        int bits = Bits(f);
        if (prefix < 0 || prefix > bits) throw new ArgumentOutOfRangeException(nameof(prefix));
        UInt128 hostMask = prefix == bits ? UInt128.Zero : MaxValue(f) >> prefix;
        var start = v & ~hostMask & MaxValue(f);
        return new IpRange(f, start, start | hostMask);
    }

    /// <summary>The prefix length when the range is exactly one CIDR block.</summary>
    public bool TryGetPrefix(out int prefix)
    {
        UInt128 span = End - Start;
        if (Start == 0 && span == MaxValue(Family)) { prefix = 0; return true; }
        UInt128 size = span + 1;
        if ((size & (size - 1)) != 0 || (Start & span) != 0) { prefix = -1; return false; }
        prefix = Bits(Family) - (int)UInt128.Log2(size);
        return true;
    }

    /// <summary>Accepts 1.2.3.4, 1.2.3.0/24, 1.2.3.0/255.255.255.0, 1.2.3.4-1.2.3.9 and the IPv6 equivalents.</summary>
    public static bool TryParse(string? text, out IpRange range)
    {
        range = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var s = text.Trim();

        int slash = s.IndexOf('/');
        if (slash >= 0)
        {
            if (!TryParseAddress(s[..slash], out var net)) return false;
            var p = s[(slash + 1)..];
            int prefix;
            if (p.Contains('.'))
            {
                if (net.AddressFamily != AddressFamily.InterNetwork || !TryParseAddress(p, out var mask) || !TryMaskToPrefix(mask, out prefix))
                    return false;
            }
            else if (!int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out prefix)) return false;
            var family = net.AddressFamily == AddressFamily.InterNetwork ? IpFamily.V4 : IpFamily.V6;
            if (prefix > Bits(family)) return false;
            range = FromCidr(net, prefix);
            return true;
        }

        int dash = s.IndexOf('-');
        if (dash > 0)
        {
            if (!TryParseAddress(s[..dash], out var a) || !TryParseAddress(s[(dash + 1)..], out var b)) return false;
            var (fa, va) = ToValue(a);
            var (fb, vb) = ToValue(b);
            if (fa != fb || va > vb) return false;
            range = new IpRange(fa, va, vb);
            return true;
        }

        if (!TryParseAddress(s, out var ip)) return false;
        range = FromAddress(ip);
        return true;
    }

    /// <summary>Strict parsing: IPv4 must be four dotted decimals (no "1.2" or hex shorthands).</summary>
    public static bool TryParseAddress(string text, out IPAddress ip)
    {
        ip = IPAddress.None;
        var s = text.Trim();
        if (s.Length == 0) return false;
        if (s.Contains(':'))
        {
            int pct = s.IndexOf('%');
            if (pct >= 0) s = s[..pct];
            if (!IPAddress.TryParse(s, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;
            ip = v6.IsIPv4MappedToIPv6 ? v6.MapToIPv4() : v6;
            return true;
        }
        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (var part in parts)
            if (part.Length is 0 or > 3 || !part.All(char.IsAsciiDigit) || int.Parse(part, CultureInfo.InvariantCulture) > 255) return false;
        return IPAddress.TryParse(s, out ip!);
    }

    private static bool TryMaskToPrefix(IPAddress mask, out int prefix)
    {
        uint m = BinaryPrimitives.ReadUInt32BigEndian(mask.GetAddressBytes());
        prefix = System.Numerics.BitOperations.PopCount(m);
        return m == (prefix == 0 ? 0u : uint.MaxValue << (32 - prefix));
    }

    public static (IpFamily Family, UInt128 Value) ToValue(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        Span<byte> b = stackalloc byte[16];
        if (!ip.TryWriteBytes(b, out int n)) throw new ArgumentException("Unsupported address", nameof(ip));
        return ip.AddressFamily switch
        {
            AddressFamily.InterNetwork when n == 4 => (IpFamily.V4, BinaryPrimitives.ReadUInt32BigEndian(b)),
            AddressFamily.InterNetworkV6 when n == 16 => (IpFamily.V6, BinaryPrimitives.ReadUInt128BigEndian(b)),
            _ => throw new ArgumentException("Unsupported address family", nameof(ip)),
        };
    }

    public static IPAddress ToAddress(IpFamily family, UInt128 value)
    {
        if (family == IpFamily.V4)
        {
            var b4 = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b4, (uint)value);
            return new IPAddress(b4);
        }
        var b16 = new byte[16];
        BinaryPrimitives.WriteUInt128BigEndian(b16, value);
        return new IPAddress(b16);
    }

    /// <summary>The Windows Firewall RemoteAddresses form: a single IP, a CIDR block, or "start-end".</summary>
    public override string ToString()
    {
        var start = ToAddress(Family, Start);
        if (IsSingle) return start.ToString();
        if (TryGetPrefix(out int p)) return $"{start}/{p}";
        return $"{start}-{ToAddress(Family, End)}";
    }
}
