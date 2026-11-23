using System.Net;
using System.Net.Sockets;

namespace ZeroLeakage.Shared.Link;

/// <summary>Validates a ZeroLeakage Server address: https:// everywhere, plain http:// only for a private LAN IP.</summary>
public static class ServerAddress
{
    public const string HttpWarning = "Unencrypted http:// — fine on your own LAN, but anyone on this network could read the traffic. Prefer https://.";

    public static bool TryNormalize(string? raw, out Uri? uri, out string? error, out string? warning)
    {
        uri = null;
        error = warning = null;
        var text = raw?.Trim() ?? "";
        if (text.Length == 0) { error = "Enter your ZeroLeakage Server address"; return false; }
        if (!text.Contains("://", StringComparison.Ordinal)) text = "https://" + text;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var u) || string.IsNullOrEmpty(u.Host))
        {
            error = "That isn't a valid server address";
            return false;
        }
        if (!string.IsNullOrEmpty(u.UserInfo) || !string.IsNullOrEmpty(u.Query) || !string.IsNullOrEmpty(u.Fragment))
        {
            error = "Use just the server address, like https://zeroleakage.example.com";
            return false;
        }
        if (u.Scheme == Uri.UriSchemeHttp)
        {
            if (!IPAddress.TryParse(u.Host.Trim('[', ']'), out var ip) || !IsPrivateLan(ip))
            {
                error = "Use https:// — plain http:// is only allowed for a private LAN IP address (like http://192.168.1.10)";
                return false;
            }
            warning = HttpWarning;
        }
        else if (u.Scheme != Uri.UriSchemeHttps)
        {
            error = "The server address must start with https://";
            return false;
        }

        var path = u.AbsolutePath.TrimEnd('/');
        uri = new Uri($"{u.Scheme}://{u.Authority}{path}");
        return true;
    }

    /// <summary>{server}/relative, keeping any base path a reverse proxy adds.</summary>
    public static Uri Combine(Uri server, string relative) =>
        new(server.AbsoluteUri.TrimEnd('/') + "/" + relative.TrimStart('/'));

    /// <summary>RFC 1918, loopback, link-local, CGNAT and IPv6 ULA / link-local addresses.</summary>
    public static bool IsPrivateLan(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC || ip.IsIPv6LinkLocal;
        }
        return false;
    }
}

/// <summary>Pairing codes look like ZL-XXXX-XXXX; accept lower case, spaces and missing dashes.</summary>
public static class PairingCode
{
    public static string? Normalize(string? raw)
    {
        if (raw is null) return null;
        var chars = raw.Trim().ToUpperInvariant().Where(char.IsLetterOrDigit).ToArray();
        var s = new string(chars);
        if (s.StartsWith("ZL", StringComparison.Ordinal) && s.Length == 10) s = s[2..];
        if (s.Length != 8 || !s.All(c => c is >= 'A' and <= 'Z' or >= '0' and <= '9')) return null;
        return $"ZL-{s[..4]}-{s[4..]}";
    }
}

/// <summary>Domain normalisation compatible with the desktop app's filter engine.</summary>
public static class DomainName
{
    public static string? Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var d = raw.Trim().ToLowerInvariant();
        if (d.StartsWith("http://", StringComparison.Ordinal)) d = d[7..];
        if (d.StartsWith("https://", StringComparison.Ordinal)) d = d[8..];
        if (d.StartsWith("||", StringComparison.Ordinal)) d = d[2..];
        if (d.StartsWith("*.", StringComparison.Ordinal)) d = d[2..];
        d = d.Split('^')[0].Split('/')[0].Split(':')[0].Trim('.');
        if (d.Length is 0 or > 253 || !d.Contains('.')) return null;
        foreach (var c in d)
            if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.' or '_')) return null;
        return d;
    }

    /// <summary>True if <paramref name="domain"/> equals <paramref name="parent"/> or is one of its subdomains.</summary>
    public static bool IsSameOrSubdomain(string domain, string parent) =>
        domain.Equals(parent, StringComparison.Ordinal) ||
        (domain.Length > parent.Length && domain.EndsWith(parent, StringComparison.Ordinal) && domain[^(parent.Length + 1)] == '.');
}
