using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ZeroLeakage.UI.Services.Dns;

public enum DnssecStatus { Off, Secure, Insecure, Bogus, NotChecked }

public sealed record DnsRecordInfo(string Name, int Type, uint Ttl, string Data, byte[]? Address)
{
    public string TypeName => DnsWire.TypeName(Type);
}

public sealed record DnsProbeResult(
    string Domain, int QType, string Resolver, string Endpoint, string HttpVersion, long LatencyMs,
    int TxId, string QueryFlags, int Rcode, string ResponseFlags, bool Ad,
    IReadOnlyList<DnsRecordInfo> Answers, IReadOnlyList<DnsRecordInfo> Authority,
    int? Ede, string? EdeText, DnssecStatus Dnssec, byte[] Query, byte[] Response, string? Error);

/// <summary>DNS wire-format helpers shared by the probe and the inspector (mirrors the Android DnsMessage).</summary>
public static class DnsWire
{
    public static string TypeName(int t) => t switch
    {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR", 15 => "MX", 16 => "TXT", 28 => "AAAA",
        33 => "SRV", 41 => "OPT", 43 => "DS", 46 => "RRSIG", 47 => "NSEC", 48 => "DNSKEY", 50 => "NSEC3",
        64 => "SVCB", 65 => "HTTPS", 257 => "CAA", _ => $"TYPE{t}",
    };

    public static string RcodeName(int r) => r switch
    {
        0 => "NOERROR", 1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 4 => "NOTIMP", 5 => "REFUSED", _ => $"RCODE{r}",
    };

    public static string EdeName(int c) => c switch
    {
        0 => "Other", 1 => "Unsupported DNSKEY algorithm", 2 => "Unsupported DS digest type", 3 => "Stale answer",
        4 => "Forged answer", 5 => "DNSSEC indeterminate", 6 => "DNSSEC bogus", 7 => "Signature expired",
        8 => "Signature not yet valid", 9 => "DNSKEY missing", 10 => "RRSIGs missing", 11 => "No zone key bit set",
        12 => "NSEC missing", 13 => "Cached error", 14 => "Not ready", 15 => "Blocked", 16 => "Censored", 17 => "Filtered",
        18 => "Prohibited", 19 => "Stale NXDOMAIN answer", 20 => "Not authoritative", 21 => "Not supported",
        22 => "No reachable authority", 23 => "Network error", 24 => "Invalid data", _ => $"EDE {c}",
    };

    public static bool IsDnssecEde(int? c) => c is >= 1 and <= 2 or >= 5 and <= 12;

    public static string Flags(byte b2, byte b3)
    {
        var f = new List<string>();
        if ((b2 & 0x80) != 0) f.Add("QR"); if ((b2 & 0x04) != 0) f.Add("AA"); if ((b2 & 0x02) != 0) f.Add("TC");
        if ((b2 & 0x01) != 0) f.Add("RD"); if ((b3 & 0x80) != 0) f.Add("RA"); if ((b3 & 0x20) != 0) f.Add("AD");
        if ((b3 & 0x10) != 0) f.Add("CD");
        return f.Count == 0 ? "—" : string.Join(' ', f);
    }

    /// <summary>Query for <paramref name="name"/> with RD, optional AD bit and an EDNS(0) OPT record (to receive Extended DNS Errors).</summary>
    public static byte[] BuildQuery(string name, int qtype, bool adBit, ushort id)
    {
        var b = new List<byte> { (byte)(id >> 8), (byte)id, 0x01, (byte)(adBit ? 0x20 : 0x00), 0, 1, 0, 0, 0, 0, 0, 1 };
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            b.Add((byte)bytes.Length); b.AddRange(bytes);
        }
        b.Add(0);
        b.AddRange(new byte[] { (byte)(qtype >> 8), (byte)qtype, 0, 1 });
        // OPT: root name, type 41, UDP 1232, ext-rcode 0, version 0, flags 0, rdlen 0
        b.AddRange(new byte[] { 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0 });
        return b.ToArray();
    }

    public static ushort U16(byte[] m, int o) => (ushort)((m[o] << 8) | m[o + 1]);

    public static int SkipName(byte[] m, int p)
    {
        while (true)
        {
            int l = m[p];
            if (l == 0) return p + 1;
            if ((l & 0xC0) == 0xC0) return p + 2;
            p += 1 + l;
        }
    }

    public static string ReadName(byte[] m, int p)
    {
        var sb = new StringBuilder();
        int jumps = 0;
        while (p < m.Length)
        {
            int l = m[p];
            if (l == 0) break;
            if ((l & 0xC0) == 0xC0) { if (++jumps > 16) break; p = ((l & 0x3F) << 8) | m[p + 1]; continue; }
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(m, p + 1, l));
            p += 1 + l;
        }
        return sb.ToString();
    }

    public static (DnsRecordInfo rec, int next) ReadRecord(byte[] m, int start)
    {
        var name = ReadName(m, start);
        int p = SkipName(m, start);
        int type = U16(m, p);
        uint ttl = (uint)((m[p + 4] << 24) | (m[p + 5] << 16) | (m[p + 6] << 8) | m[p + 7]);
        int len = U16(m, p + 8);
        int r = p + 10;
        var raw = m.AsSpan(r, len).ToArray();
        string data = type switch
        {
            1 when len == 4 => new System.Net.IPAddress(raw).ToString(),
            28 when len == 16 => new System.Net.IPAddress(raw).ToString(),
            2 or 5 or 12 or 39 => ReadName(m, r),
            15 => $"{U16(m, r)} {ReadName(m, r + 2)}",
            16 => Txt(raw),
            6 => $"{ReadName(m, r)} {ReadName(m, SkipName(m, r))}",
            33 => $"{U16(m, r)} {U16(m, r + 2)} {U16(m, r + 4)} {ReadName(m, r + 6)}",
            64 or 65 => $"priority {U16(m, r)} → {(ReadName(m, r + 2) is { Length: > 0 } t ? t : ".")}",
            46 => $"signs {TypeName(U16(m, r))} · alg {m[r + 2]} · key {U16(m, r + 16)}",
            _ => $"{len} bytes",
        };
        return (new DnsRecordInfo(name, type, ttl, data, type is 1 or 28 ? raw : null), r + len);
    }

    private static string Txt(byte[] raw)
    {
        var parts = new List<string>();
        int p = 0;
        while (p < raw.Length) { int l = raw[p]; parts.Add("\"" + Encoding.UTF8.GetString(raw, p + 1, Math.Min(l, raw.Length - p - 1)) + "\""); p += 1 + l; }
        return string.Join(' ', parts);
    }

    public static string HexDump(byte[] bytes, int limit = 1024)
    {
        int n = Math.Min(bytes.Length, limit);
        var sb = new StringBuilder();
        for (int off = 0; off < n; off += 16)
        {
            sb.Append(off.ToString("x4")).Append("  ");
            for (int i = 0; i < 16; i++)
            {
                sb.Append(off + i < n ? bytes[off + i].ToString("x2") + " " : "   ");
                if (i == 7) sb.Append(' ');
            }
            sb.Append(' ');
            for (int i = 0; i < Math.Min(16, n - off); i++) { byte c = bytes[off + i]; sb.Append(c is >= 0x20 and <= 0x7E ? (char)c : '.'); }
            sb.Append('\n');
        }
        if (bytes.Length > limit) sb.Append($"… {bytes.Length - limit} more bytes");
        return sb.ToString().TrimEnd();
    }
}

/// <summary>
/// Performs one real DNS-over-HTTPS lookup (RFC 8484 POST) with the AD bit set, so the inspector can show
/// genuine answers, TTLs, DNSSEC status and Extended DNS Errors for any domain in the feed.
/// </summary>
public static class DohProbe
{
    private static readonly HttpClient Http = new(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) })
    {
        Timeout = TimeSpan.FromSeconds(8),
        DefaultRequestVersion = new Version(2, 0),
    };

    public static async Task<DnsProbeResult> ResolveAsync(string domain, int qtype, string resolverName, string endpoint, bool dnssec, CancellationToken ct = default)
    {
        ushort id = (ushort)Random.Shared.Next(1, 0xFFFF);
        var query = DnsWire.BuildQuery(domain, qtype, dnssec, id);
        var sw = Stopwatch.StartNew();
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new ByteArrayContent(query) };
            req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
            using var resp = await Http.SendAsync(req, ct);
            resp.EnsureSuccessStatusCode();
            var msg = await resp.Content.ReadAsByteArrayAsync(ct);
            sw.Stop();
            return Parse(domain, qtype, resolverName, endpoint, $"HTTP/{resp.Version}", sw.ElapsedMilliseconds, query, msg, dnssec);
        }
        catch (Exception ex)
        {
            return new DnsProbeResult(domain, qtype, resolverName, endpoint, "", sw.ElapsedMilliseconds, id, DnsWire.Flags(query[2], query[3]),
                -1, "", false, Array.Empty<DnsRecordInfo>(), Array.Empty<DnsRecordInfo>(), null, null, DnssecStatus.NotChecked,
                query, Array.Empty<byte>(), ex is TaskCanceledException ? "Timed out" : ex.Message);
        }
    }

    public static DnsProbeResult Parse(string domain, int qtype, string resolver, string endpoint, string http, long ms, byte[] query, byte[] m, bool dnssec)
    {
        int qd = DnsWire.U16(m, 4), an = DnsWire.U16(m, 6), ns = DnsWire.U16(m, 8), ar = DnsWire.U16(m, 10);
        int p = 12;
        for (int i = 0; i < qd; i++) p = DnsWire.SkipName(m, p) + 4;
        var answers = new List<DnsRecordInfo>();
        for (int i = 0; i < an; i++) { var (r, n) = DnsWire.ReadRecord(m, p); answers.Add(r); p = n; }
        var authority = new List<DnsRecordInfo>();
        for (int i = 0; i < ns; i++) { var (r, n) = DnsWire.ReadRecord(m, p); authority.Add(r); p = n; }
        int? ede = null; string? edeText = null;
        for (int i = 0; i < ar; i++)
        {
            int nameEnd = DnsWire.SkipName(m, p);
            int type = DnsWire.U16(m, nameEnd);
            int rdlen = DnsWire.U16(m, nameEnd + 8);
            if (type == 41)
            {
                int o = nameEnd + 10, end = o + rdlen;
                while (o + 4 <= end)
                {
                    int code = DnsWire.U16(m, o), len = DnsWire.U16(m, o + 2);
                    if (code == 15 && len >= 2)
                    {
                        ede = DnsWire.U16(m, o + 4);
                        if (len > 2) edeText = Encoding.UTF8.GetString(m, o + 6, len - 2);
                    }
                    o += 4 + len;
                }
            }
            p = nameEnd + 10 + rdlen;
        }
        int rcode = m[3] & 0x0F;
        bool ad = (m[3] & 0x20) != 0;
        var status = !dnssec ? DnssecStatus.Off
            : rcode == 2 && DnsWire.IsDnssecEde(ede) ? DnssecStatus.Bogus
            : ad ? DnssecStatus.Secure : DnssecStatus.Insecure;
        return new DnsProbeResult(domain, qtype, resolver, endpoint, http, ms, DnsWire.U16(query, 0), DnsWire.Flags(query[2], query[3]),
            rcode, DnsWire.Flags(m[2], m[3]), ad, answers, authority, ede, edeText, status, query, m, null);
    }
}
