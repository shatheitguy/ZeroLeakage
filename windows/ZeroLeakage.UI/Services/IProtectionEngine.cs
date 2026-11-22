using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ZeroLeakage.UI.Models;

namespace ZeroLeakage.UI.Services;

/// <summary>
/// The single seam between the UI and the protection back-end
/// (firewall rule group "ZeroLeakage_Core", DNS/DoH filter, telemetry purger, DeepScan AV, snapshots).
///
/// Events may be raised on any thread — view-models marshal to the dispatcher.
/// <see cref="SimulatedProtectionEngine"/> is a self-contained stand-in so the UI runs on its own;
/// swap it for the real Core service client in App.xaml.cs.
/// </summary>
public interface IProtectionEngine : IDisposable
{
    event EventHandler<FeedEvent>? FeedEventRaised;
    event EventHandler<EngineStats>? StatsUpdated;
    event EventHandler<ConnectionRequest>? ConnectionRequested;

    ProtectionMode Mode { get; }

    void Start();

    Task SetModeAsync(ProtectionMode mode);
    Task SubmitDecisionAsync(ConnectionRequest request, ConnectDecision decision);

    Task BlockDomainAsync(string domain);
    Task UnblockDomainAsync(string domain);
    Task KillAppNetworkAsync(string processName);
    Task SetAppAccessAsync(AppRule app, NetworkScope scope, bool allowed);
    Task SetGlobalScopeAsync(NetworkScope scope, bool allowed);

    Task<DateTime> OpenUpdateWindowAsync(TimeSpan duration);
    Task CloseUpdateWindowAsync();
    Task RestoreDefaultsAsync();

    IReadOnlyList<AppRule> GetAppRules();
    IReadOnlyList<BlocklistSource> GetBlocklists();
    IReadOnlyList<DohResolver> GetResolvers();
    IReadOnlyList<TelemetryServiceStatus> GetTelemetryServices();
    Task SetBlocklistEnabledAsync(BlocklistSource list, bool enabled);
    Task SetResolverAsync(DohResolver resolver);
    Task<double> WipeTraceLogsAsync(IProgress<double>? progress, CancellationToken ct = default);

    Task SetRealtimeProtectionAsync(bool enabled);
    Task<ScanResult> RunScanAsync(ScanKind kind, IProgress<ScanProgress> progress, CancellationToken ct);
    IReadOnlyList<QuarantineItem> GetQuarantine();
    Task RestoreQuarantinedAsync(QuarantineItem item);
    Task DeleteQuarantinedAsync(QuarantineItem item);

    IReadOnlyList<SystemSnapshot> GetSnapshots();
    Task<SystemSnapshot> CreateSnapshotAsync(string name);
    Task RestoreSnapshotAsync(SystemSnapshot snapshot);

    Task<AuditReport> RunAuditAsync(IProgress<AuditProgress> progress, CancellationToken ct = default);
    Task ApplyRecommendationsAsync(IEnumerable<AuditRecommendation> recommendations);
}
