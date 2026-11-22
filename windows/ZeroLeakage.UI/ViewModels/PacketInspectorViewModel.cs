using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.Mvvm;
using ZeroLeakage.UI.Services;
using ZeroLeakage.UI.Services.Dns;

namespace ZeroLeakage.UI.ViewModels;

public sealed class AnswerRow
{
    public required string Type { get; init; }
    public required string Data { get; init; }
    public required string Name { get; init; }
    public required string Ttl { get; init; }
    public string? CountryCode { get; init; }
    public string? Location { get; init; }
    public string? LocationNote { get; init; }
    public bool HasLocation => Location is not null;
    public bool HasCode => CountryCode is not null;
}

/// <summary>
/// Packet inspector for one feed event: the event as the engine saw it, plus a real DNS-over-HTTPS lookup of
/// the destination (A + AAAA, AD bit for DNSSEC) with answers, TTLs, flags, Extended DNS Errors, GeoIP country
/// per IP and raw hex.
/// </summary>
public sealed class PacketInspectorViewModel : ObservableObject
{
    private readonly IProtectionEngine _engine;
    private bool _isBusy;
    private string _status = "";
    private DnsProbeResult? _a, _aaaa;

    public PacketInspectorViewModel(FeedEvent e, IProtectionEngine engine)
    {
        Event = e;
        _engine = engine;
        RefreshCommand = new AsyncRelayCommand(RunAsync, () => !IsBusy);
        CopyCommand = new RelayCommand(() => { try { Clipboard.SetText(Report()); Status = "Report copied to clipboard"; } catch { /* clipboard busy */ } });
        BlockCommand = new RelayCommand(() => { App.Filters.Block(Event.Destination); Status = $"Blocked {Event.Destination}"; }, () => IsDomain);
        AllowCommand = new RelayCommand(() => { App.Filters.Allow(Event.Destination); Status = $"Allowlisted {Event.Destination}"; }, () => IsDomain);
    }

    public FeedEvent Event { get; }
    public bool IsDomain => !IPAddress.TryParse(Event.Destination, out _);
    public string Title => Event.Destination;
    public string Verdict => Event.VerdictText;
    public string When => Event.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff");
    public string Process => Event.ProcessText;
    public string Destination => Event.DestinationText;
    public string Protocol => Event.Port switch { 443 => "TCP 443 · HTTPS / TLS", 80 => "TCP 80 · HTTP", 53 => "UDP 53 · DNS", 853 => "TCP 853 · DNS-over-TLS", _ => $"port {Event.Port}" };
    public string RuleList => Event.Match?.ListName ?? "—";
    public string Rule => Event.Match?.Rule ?? "no filter rule (decided by mode / firewall)";
    public string Matched => Event.Match?.Matched ?? "—";

    public ObservableCollection<AnswerRow> Answers { get; } = new();
    public ObservableCollection<AnswerRow> Authority { get; } = new();

    public bool IsBusy { get => _isBusy; private set => SetProperty(ref _isBusy, value); }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }

    public string ResolverText => _a is null ? "—" : $"{_a.Resolver}";
    public string EndpointText => _a?.Endpoint ?? "—";
    public string TransportText => _a is null ? "—" : $"DNS-over-HTTPS (RFC 8484) · {(_a.HttpVersion.Length > 0 ? _a.HttpVersion : "?")} · TLS";
    public string LatencyText => _a is null ? "—" : $"A {_a.LatencyMs} ms" + (_aaaa is null ? "" : $" · AAAA {_aaaa.LatencyMs} ms");
    public string QueryText => _a is null ? "—" : $"{Event.Destination}  IN A / AAAA · id 0x{_a.TxId:x4} · flags [{_a.QueryFlags}] · EDNS UDP 1232";
    public string RcodeText => _a is null ? "—" : _a.Error ?? DnsWire.RcodeName(_a.Rcode);
    public string ResponseFlagsText => _a?.ResponseFlags ?? "—";
    public string SizesText => _a is null ? "—" : $"query {_a.Query.Length} B · response {_a.Response.Length} B" + (_aaaa is null ? "" : $" / {_aaaa.Response.Length} B");
    public string DnssecText => _a is null ? "—" : DnsTelemetryViewModel.DnssecLabel(_a.Dnssec);
    public string DnssecExplain => _a?.Dnssec switch
    {
        DnssecStatus.Secure => "The resolver verified the signature chain from the root to this domain.",
        DnssecStatus.Insecure => "This domain isn't DNSSEC-signed, so the answer's authenticity can't be proven cryptographically.",
        DnssecStatus.Bogus => "Signatures failed to verify — possible spoofing. The resolver refused the answer.",
        DnssecStatus.Off => "DNSSEC checking is off (DNS → Resolver & DNSSEC).",
        _ => "",
    };
    public DnssecStatus Dnssec => _a?.Dnssec ?? DnssecStatus.NotChecked;
    public string EdeText => _a?.Ede is { } c ? DnsWire.EdeName(c) + (_a.EdeText is { Length: > 0 } t ? $" — {t}" : "") : "none";
    public string QueryHex => _a is null ? "" : DnsWire.HexDump(_a.Query);
    public string ResponseHex => _a is null ? "" : DnsWire.HexDump(_a.Response);
    public bool HasLookup => _a is not null;
    public string GeoHint => App.GeoIp.IsInstalled ? "" : "Download the GeoIP database (DNS → Resolver & DNSSEC) to see each IP's country.";

    public ICommand RefreshCommand { get; }
    public ICommand CopyCommand { get; }
    public ICommand BlockCommand { get; }
    public ICommand AllowCommand { get; }

    public async Task RunAsync()
    {
        IsBusy = true;
        Answers.Clear();
        Authority.Clear();
        try
        {
            if (!IsDomain)
            {
                // The destination is already an IP address — nothing to resolve, just locate it.
                Answers.Add(Row(new DnsRecordInfo(Event.Destination, Event.Destination.Contains(':') ? 28 : 1, 0,
                    Event.Destination, IPAddress.Parse(Event.Destination).GetAddressBytes())) );
                Status = "Destination is an IP address — no DNS lookup needed.";
                return;
            }
            var r = _engine.CurrentResolver;
            Status = $"Resolving live via {r.Name}…";
            bool dnssec = _engine.DnssecEnabled;
            _a = await DohProbe.ResolveAsync(Event.Destination, 1, r.Name, r.Address, dnssec);
            _aaaa = await DohProbe.ResolveAsync(Event.Destination, 28, r.Name, r.Address, dnssec);
            foreach (var rec in _a.Answers) Answers.Add(Row(rec));
            foreach (var rec in _aaaa.Answers.Where(x => x.Type == 28)) Answers.Add(Row(rec));
            foreach (var rec in _a.Authority) Authority.Add(Row(rec));
            Status = _a.Error is null ? $"Live lookup done · {Answers.Count} records" : $"Lookup failed: {_a.Error}";
        }
        finally
        {
            IsBusy = false;
            foreach (var n in new[] { nameof(ResolverText), nameof(EndpointText), nameof(TransportText), nameof(LatencyText), nameof(QueryText),
                         nameof(RcodeText), nameof(ResponseFlagsText), nameof(SizesText), nameof(DnssecText), nameof(DnssecExplain), nameof(Dnssec),
                         nameof(EdeText), nameof(QueryHex), nameof(ResponseHex), nameof(HasLookup), nameof(GeoHint) })
                OnPropertyChanged(n);
        }
    }

    private static AnswerRow Row(DnsRecordInfo rec)
    {
        GeoInfo? geo = rec.Address is { } ip ? App.GeoIp.Lookup(ip) : null;
        return new AnswerRow
        {
            Type = rec.TypeName, Data = rec.Data, Name = rec.Name, Ttl = rec.Ttl > 0 ? $"TTL {rec.Ttl}s" : "",
            CountryCode = geo?.Code, Location = geo?.Label ?? (rec.Address is not null && !App.GeoIp.IsInstalled ? "location: GeoIP database not downloaded" : null),
            LocationNote = geo?.Note,
        };
    }

    private string Report()
    {
        var sb = new StringBuilder();
        sb.AppendLine("ZeroLeakage packet report");
        sb.AppendLine($"time      {When}");
        sb.AppendLine($"verdict   {Verdict} · {Event.Category}");
        sb.AppendLine($"process   {Process}");
        sb.AppendLine($"dest      {Destination} ({Protocol})");
        if (Event.Match is { } m) sb.AppendLine($"rule      {m.Rule} ({m.ListName})");
        if (_a is not null)
        {
            sb.AppendLine($"resolver  {_a.Resolver} {_a.Endpoint} {_a.HttpVersion} {LatencyText}");
            sb.AppendLine($"query     {QueryText}");
            sb.AppendLine($"rcode     {RcodeText} flags=[{_a.ResponseFlags}] {SizesText}");
            sb.AppendLine($"dnssec    {DnssecText} · EDE {EdeText}");
        }
        foreach (var a in Answers) sb.AppendLine($"answer    {a.Name} {a.Ttl} {a.Type} {a.Data}{(a.Location is null ? "" : $" [{a.Location}]")}");
        return sb.ToString();
    }
}
