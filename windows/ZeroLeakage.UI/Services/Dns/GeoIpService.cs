using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using ZeroLeakage.UI.Mvvm;
using ZeroLeakage.UI.ViewModels;

namespace ZeroLeakage.UI.Services.Dns;

/// <summary>Where an IP lives. <see cref="Code"/> is ISO-3166 alpha-2, or null for special ranges.</summary>
public sealed record GeoInfo(string? Code, string Name, string? Note = null)
{
    public string Label => Code is null ? Name : $"{Name} ({Code})";
}

/// <summary>
/// Offline IP → country lookup using the DB-IP "IP to Country Lite" database (CC BY 4.0), downloaded only
/// when the user asks and stored in %LocalAppData%\ZeroLeakage\geoip. Lookups never leave the PC.
/// IPv6 ranges are keyed on their upper 64 bits. Same binary layout as the Android app.
/// </summary>
public sealed class GeoIpService : ObservableObject
{
    public const string Attribution = "IP geolocation by DB-IP.com (CC BY 4.0)";
    private const int Magic = 0x5A4C4731;

    private readonly string _file = Path.Combine(UiSettingsStore.Directory, "geoip", "country.bin");
    private uint[] _s4 = Array.Empty<uint>(), _e4 = Array.Empty<uint>();
    private ulong[] _s6 = Array.Empty<ulong>(), _e6 = Array.Empty<ulong>();
    private ushort[] _c4 = Array.Empty<ushort>(), _c6 = Array.Empty<ushort>();
    private bool _installed, _busy;
    private string _status = "Not downloaded";

    public bool IsInstalled { get => _installed; private set { if (SetProperty(ref _installed, value)) OnPropertyChanged(nameof(IsNotInstalled)); } }
    public bool IsNotInstalled => !_installed;
    public bool IsBusy { get => _busy; private set => SetProperty(ref _busy, value); }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }

    public GeoIpService()
    {
        if (File.Exists(_file)) _ = Task.Run(LoadFile);
    }

    public GeoInfo? Lookup(string ip) => IPAddress.TryParse(ip, out var a) ? Lookup(a.GetAddressBytes()) : null;

    public GeoInfo? Lookup(byte[] ip)
    {
        if (Special(ip) is { } s) return s;
        if (!_installed) return null;
        ushort cc = ip.Length == 4 ? Search4(BinaryPrimitives.ReadUInt32BigEndian(ip)) : ip.Length == 16 ? Search6(BinaryPrimitives.ReadUInt64BigEndian(ip)) : (ushort)0;
        if (cc == 0) return new GeoInfo(null, "Unknown location");
        var code = $"{(char)(cc >> 8)}{(char)(cc & 0xFF)}";
        return new GeoInfo(code, CountryName(code));
    }

    private ushort Search4(uint ip)
    {
        int lo = 0, hi = _s4.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (ip < _s4[mid]) hi = mid - 1; else if (ip > _e4[mid]) lo = mid + 1; else return _c4[mid];
        }
        return 0;
    }

    private ushort Search6(ulong ip)
    {
        int lo = 0, hi = _s6.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (ip < _s6[mid]) hi = mid - 1; else if (ip > _e6[mid]) lo = mid + 1; else return _c6[mid];
        }
        return 0;
    }

    public static string CountryName(string code)
    {
        try { return new RegionInfo(code).EnglishName; } catch { return code; }
    }

    public static GeoInfo? Special(byte[] ip)
    {
        if (ip.Length == 4)
        {
            int a = ip[0], b = ip[1];
            if (a == 0 && b == 0 && ip[2] == 0 && ip[3] == 0) return new(null, "Null route", "0.0.0.0 — sinkholed / blocked answer");
            if (a == 10 || (a == 172 && b is >= 16 and <= 31) || (a == 192 && b == 168)) return new(null, "Private network", "RFC 1918 — stays on your LAN");
            if (a == 100 && b is >= 64 and <= 127) return new(null, "Carrier-grade NAT", "RFC 6598 — inside your ISP");
            if (a == 127) return new(null, "Loopback", "This PC");
            if (a == 169 && b == 254) return new(null, "Link-local", "RFC 3927");
            if (a is >= 224 and <= 239) return new(null, "Multicast");
            if (a >= 240) return new(null, "Reserved");
            return null;
        }
        if (ip.Length == 16)
        {
            var addr = new IPAddress(ip);
            if (addr.Equals(IPAddress.IPv6None)) return new(null, "Null route", ":: — sinkholed / blocked answer");
            if (addr.Equals(IPAddress.IPv6Loopback)) return new(null, "Loopback", "This PC");
            if ((ip[0] & 0xFE) == 0xFC) return new(null, "Private network", "Unique local (fc00::/7)");
            if (addr.IsIPv6LinkLocal) return new(null, "Link-local", "fe80::/10");
            if (ip[0] == 0xFF) return new(null, "Multicast");
        }
        return null;
    }

    public void Delete()
    {
        try { File.Delete(_file); } catch { /* ignore */ }
        _s4 = _e4 = Array.Empty<uint>(); _s6 = _e6 = Array.Empty<ulong>(); _c4 = _c6 = Array.Empty<ushort>();
        IsInstalled = false;
        Status = "Not downloaded";
    }

    public async Task DownloadAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        string? lastError = null;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("ZeroLeakage-Windows/1.1");
            for (int back = 0; back <= 2; back++)
            {
                var month = DateTime.UtcNow.AddMonths(-back);
                var stamp = month.ToString("yyyy-MM", CultureInfo.InvariantCulture);
                Status = $"Downloading DB-IP Country Lite {stamp}…";
                try
                {
                    using var resp = await http.GetAsync($"https://download.db-ip.com/free/dbip-country-lite-{stamp}.csv.gz", HttpCompletionOption.ResponseHeadersRead);
                    if (!resp.IsSuccessStatusCode) { lastError = $"HTTP {(int)resp.StatusCode}"; continue; }
                    await using var gz = new GZipStream(await resp.Content.ReadAsStreamAsync(), CompressionMode.Decompress);
                    Status = "Indexing ranges…";
                    var source = $"DB-IP Country Lite {stamp}";
                    await Task.Run(() => BuildFrom(gz, source));
                    return;
                }
                catch (Exception ex) { lastError = ex.Message; }
            }
            Status = "Download failed: " + (lastError ?? "unknown error");
        }
        finally { IsBusy = false; }
    }

    private void BuildFrom(Stream csv, string source)
    {
        var s4 = new List<uint>(400_000); var e4 = new List<uint>(400_000); var c4 = new List<ushort>(400_000);
        var s6 = new List<ulong>(400_000); var e6 = new List<ulong>(400_000); var c6 = new List<ushort>(400_000);
        using var reader = new StreamReader(csv);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var parts = line.Split(',');
            if (parts.Length < 3) continue;
            var code = parts[2].Trim().Trim('"').ToUpperInvariant();
            if (code.Length != 2 || code == "ZZ") continue;
            ushort cc = (ushort)((code[0] << 8) | code[1]);
            if (!IPAddress.TryParse(parts[0].Trim('"'), out var a) || !IPAddress.TryParse(parts[1].Trim('"'), out var b)) continue;
            var ab = a.GetAddressBytes(); var bb = b.GetAddressBytes();
            if (ab.Length == 4)
            {
                uint s = BinaryPrimitives.ReadUInt32BigEndian(ab), e = BinaryPrimitives.ReadUInt32BigEndian(bb);
                int n = s4.Count;
                if (n > 0 && c4[n - 1] == cc && e4[n - 1] + 1 == s) { e4[n - 1] = e; continue; }
                s4.Add(s); e4.Add(e); c4.Add(cc);
            }
            else
            {
                ulong s = BinaryPrimitives.ReadUInt64BigEndian(ab), e = BinaryPrimitives.ReadUInt64BigEndian(bb);
                int n = s6.Count;
                if (n > 0 && s <= e6[n - 1]) { if (c6[n - 1] == cc && e > e6[n - 1]) e6[n - 1] = e; continue; }
                if (n > 0 && c6[n - 1] == cc && e6[n - 1] + 1 == s) { e6[n - 1] = e; continue; }
                s6.Add(s); e6.Add(e); c6.Add(cc);
            }
        }
        if (s4.Count < 10_000) throw new InvalidDataException("Database looks incomplete");

        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        var tmp = _file + ".tmp";
        using (var w = new BinaryWriter(File.Create(tmp)))
        {
            // Big-endian layout identical to the Android file (Java DataOutputStream).
            void I32(int v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(b, v); w.Write(b); }
            void I64(long v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(b, v); w.Write(b); }
            void I16(ushort v) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, v); w.Write(b); }
            I32(Magic);
            var src = System.Text.Encoding.UTF8.GetBytes(source);
            I16((ushort)src.Length); w.Write(src);
            I32(s4.Count);
            for (int i = 0; i < s4.Count; i++) { I32((int)s4[i]); I32((int)e4[i]); I16(c4[i]); }
            I32(s6.Count);
            for (int i = 0; i < s6.Count; i++) { I64((long)s6[i]); I64((long)e6[i]); I16(c6[i]); }
        }
        File.Move(tmp, _file, overwrite: true);
        Apply(s4.ToArray(), e4.ToArray(), c4.ToArray(), s6.ToArray(), e6.ToArray(), c6.ToArray(), source);
    }

    private void LoadFile()
    {
        try
        {
            using var r = new BinaryReader(new BufferedStream(File.OpenRead(_file), 1 << 16));
            int I32() => BinaryPrimitives.ReadInt32BigEndian(r.ReadBytes(4));
            long I64() => BinaryPrimitives.ReadInt64BigEndian(r.ReadBytes(8));
            ushort U16() => BinaryPrimitives.ReadUInt16BigEndian(r.ReadBytes(2));
            if (I32() != Magic) throw new InvalidDataException("bad magic");
            var source = System.Text.Encoding.UTF8.GetString(r.ReadBytes(U16()));
            int n4 = I32();
            var s4 = new uint[n4]; var e4 = new uint[n4]; var c4 = new ushort[n4];
            for (int i = 0; i < n4; i++) { s4[i] = (uint)I32(); e4[i] = (uint)I32(); c4[i] = U16(); }
            int n6 = I32();
            var s6 = new ulong[n6]; var e6 = new ulong[n6]; var c6 = new ushort[n6];
            for (int i = 0; i < n6; i++) { s6[i] = (ulong)I64(); e6[i] = (ulong)I64(); c6[i] = U16(); }
            Apply(s4, e4, c4, s6, e6, c6, source);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(ex);
            Ui.Post(() => Status = "Database file was corrupt — download it again");
        }
    }

    private void Apply(uint[] s4, uint[] e4, ushort[] c4, ulong[] s6, ulong[] e6, ushort[] c6, string source)
    {
        _s4 = s4; _e4 = e4; _c4 = c4; _s6 = s6; _e6 = e6; _c6 = c6;
        var size = new FileInfo(_file).Length;
        Ui.Post(() =>
        {
            IsInstalled = true;
            Status = $"{source} · {s4.Length + s6.Length:N0} ranges · {size / 1024.0 / 1024.0:0.0} MB";
        });
    }
}
