using System;
using System.Collections.Generic;
using ZeroLeakage.UI.Mvvm;

namespace ZeroLeakage.UI.Models;

public enum ProtectionMode { Balanced = 1, StrictGuard = 2, TotalLockdown = 3 }
public enum FeedVerdict { Blocked, Allowed, Prompted }
public enum FeedFilter { All, Blocked, Allowed }
public enum NetworkScope { WiFi, Lan, Wan }
public enum ConnectDecision { Allow, Block, AllowOnce }
public enum ScanKind { Quick, Full }
public enum AuditSeverity { Good, Warning, Critical }
public enum ImpactLevel { None, Low, Medium }

/// <summary>One line of the live packet / DNS feed.</summary>
public sealed record FeedEvent(
    DateTime Timestamp,
    FeedVerdict Verdict,
    string Process,
    string? Service,
    string Destination,
    int Port,
    string Category)
{
    public string TimeText => Timestamp.ToString("HH:mm:ss");
    public string VerdictText => Verdict switch
    {
        FeedVerdict.Blocked => "BLOCKED",
        FeedVerdict.Allowed => "ALLOWED",
        _ => "PROMPT",
    };
    public string ProcessText => Service is null ? Process : $"{Service} ({Process})";
    public string DestinationText => Port > 0 ? $"{Destination}:{Port}" : Destination;
    public string SearchKey { get; } = $"{Process} {Service} {Destination} {Category}".ToLowerInvariant();
}

/// <summary>An unapproved executable asking to connect (Mode 2 "Ask to Connect").</summary>
public sealed record ConnectionRequest(
    Guid Id,
    string ProcessName,
    string ProcessPath,
    string? Publisher,
    bool IsSigned,
    string Destination,
    string RemoteIp,
    int Port,
    string Protocol);

public sealed class AppRule : ObservableObject
{
    private bool _wifiAllowed = true, _lanAllowed = true, _wanAllowed = true;
    private long _blockedAttempts;

    public required string Name { get; init; }
    public required string Path { get; init; }
    public string? Publisher { get; init; }
    public bool IsSigned { get; init; }

    public string Initial => Name.Length > 0 ? Name[..1].ToUpperInvariant() : "?";
    public string SignatureText => IsSigned ? $"Signed · {Publisher}" : "Unsigned";

    public bool WifiAllowed { get => _wifiAllowed; set { if (SetProperty(ref _wifiAllowed, value)) OnPropertyChanged(nameof(IsFullyKilled)); } }
    public bool LanAllowed { get => _lanAllowed; set { if (SetProperty(ref _lanAllowed, value)) OnPropertyChanged(nameof(IsFullyKilled)); } }
    public bool WanAllowed { get => _wanAllowed; set { if (SetProperty(ref _wanAllowed, value)) OnPropertyChanged(nameof(IsFullyKilled)); } }
    public bool IsFullyKilled => !WifiAllowed && !LanAllowed && !WanAllowed;

    public long BlockedAttempts { get => _blockedAttempts; set => SetProperty(ref _blockedAttempts, value); }
}

public sealed class BlocklistSource : ObservableObject
{
    private bool _isEnabled;
    public required string Name { get; init; }
    public required string Description { get; init; }
    public int EntryCount { get; init; }
    public string EntryText => $"{EntryCount:N0} domains";
    public bool IsEnabled { get => _isEnabled; set => SetProperty(ref _isEnabled, value); }
}

public sealed record DohResolver(string Name, string Address, string Note);

public sealed record TelemetryServiceStatus(string Name, string DisplayName, bool IsNeutralized)
{
    public string StateText => IsNeutralized ? "DISABLED" : "RUNNING";
}

public sealed record QuarantineItem(
    Guid Id,
    string FileName,
    string OriginalPath,
    string Sha256,
    string ThreatName,
    DateTime QuarantinedAt,
    long SizeBytes)
{
    public string ShortHash => Sha256.Length > 20 ? $"{Sha256[..12]}…{Sha256[^8..]}" : Sha256;
    public string DateText => QuarantinedAt.ToString("dd MMM yyyy · HH:mm");
    public string SizeText => SizeBytes >= 1_048_576 ? $"{SizeBytes / 1_048_576d:0.0} MB" : $"{SizeBytes / 1024d:0} KB";
}

public sealed record SystemSnapshot(Guid Id, string Name, DateTime CreatedAt, string Kind, long SizeBytes)
{
    public string DateText => CreatedAt.ToString("dd MMM yyyy · HH:mm");
    public string SizeText => $"{SizeBytes / 1_048_576d:0.0} MB";
}

public readonly record struct EngineStats(
    long TelemetryBlocked,
    double EtlMegabytesWiped,
    long DnsBlocked,
    int DohLatencyMs,
    int FirewallRules,
    long ExeBlocked,
    bool RealtimeProtection,
    DateTime? LastScan,
    int QuarantinedCount,
    double EventsPerSecond,
    DateTime? UpdateWindowEnds);

public readonly record struct ScanProgress(double Percent, string CurrentPath, long FilesScanned, int ThreatsFound);
public sealed record ScanResult(ScanKind Kind, long FilesScanned, int ThreatsFound, TimeSpan Duration);
public readonly record struct AuditProgress(double Percent, string Stage);

public sealed record AuditCategory(string Name, string Finding, AuditSeverity Severity)
{
    public string SeverityText => Severity switch
    {
        AuditSeverity.Good => "OK",
        AuditSeverity.Warning => "WEAK",
        _ => "EXPOSED",
    };
}

public sealed class AuditRecommendation : ObservableObject
{
    private bool _isSelected = true;
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public required string ImpactTag { get; init; }
    public ImpactLevel Impact { get; init; }
    public int ScoreGain { get; init; }
    public bool IsSelected { get => _isSelected; set => SetProperty(ref _isSelected, value); }
}

public sealed record AuditReport(int Score, IReadOnlyList<AuditCategory> Categories, IReadOnlyList<AuditRecommendation> Recommendations);
