using System;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.Mvvm;
using ZeroLeakage.UI.Services;

namespace ZeroLeakage.UI.ViewModels;

public sealed class DashboardViewModel : ObservableObject
{
    private const int MaxFeedItems = 400;

    private readonly IProtectionEngine _engine;
    private readonly ConcurrentQueue<FeedEvent> _pending = new();
    private readonly DispatcherTimer _flush;
    private readonly DispatcherTimer _uptime;
    private readonly DateTime _sessionStart = DateTime.Now;

    private EngineStats _stats;
    private string _searchText = "";
    private FeedFilter _filter = FeedFilter.All;
    private bool _isPaused;
    private long _blockedSession, _allowedSession;

    public DashboardViewModel(MainViewModel shell, IProtectionEngine engine)
    {
        Shell = shell;
        _engine = engine;

        FeedView = CollectionViewSource.GetDefaultView(FeedItems);
        FeedView.Filter = FilterFeed;

        BlockDomainCommand = new AsyncRelayCommand(async p =>
        {
            if (p is not FeedEvent e) return;
            await _engine.BlockDomainAsync(e.Destination);
            Shell.ShowSnackbar($"Blocked domain {e.Destination}");
        });
        InspectCommand = new RelayCommand(p =>
        {
            if (p is not FeedEvent e) return;
            var w = new ZeroLeakage.UI.Views.PacketInspectorWindow(new PacketInspectorViewModel(e, _engine))
            {
                Owner = System.Windows.Application.Current?.MainWindow,
            };
            w.Show();
        });
        KillAppNetworkCommand = new AsyncRelayCommand(async p =>
        {
            if (p is not FeedEvent e) return;
            await _engine.KillAppNetworkAsync(e.Process);
            Shell.Firewall.MarkKilled(e.Process);
            Shell.ShowSnackbar($"Network killed for {e.Process}");
        });
        ClearFeedCommand = new RelayCommand(() => FeedItems.Clear());
        TogglePauseCommand = new RelayCommand(() => IsPaused = !IsPaused);

        engine.FeedEventRaised += (_, e) => { if (!_isPaused) _pending.Enqueue(e); };
        engine.StatsUpdated += (_, s) => Ui.Post(() => Stats = s);

        // Batch feed inserts so a burst of packets never floods the dispatcher.
        _flush = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(120) };
        _flush.Tick += (_, _) => Flush();
        _flush.Start();

        _uptime = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _uptime.Tick += (_, _) => OnPropertyChanged(nameof(UptimeText));
        _uptime.Start();
    }

    public MainViewModel Shell { get; }

    // ───────────── feed ─────────────
    public ObservableCollection<FeedEvent> FeedItems { get; } = new();
    public ICollectionView FeedView { get; }

    public string SearchText
    {
        get => _searchText;
        set { if (SetProperty(ref _searchText, value ?? "")) FeedView.Refresh(); }
    }

    public FeedFilter Filter
    {
        get => _filter;
        set { if (SetProperty(ref _filter, value)) FeedView.Refresh(); }
    }

    public bool IsPaused
    {
        get => _isPaused;
        set { if (SetProperty(ref _isPaused, value)) OnPropertyChanged(nameof(PauseText)); }
    }

    public string PauseText => IsPaused ? "Resume" : "Pause";

    public ICommand BlockDomainCommand { get; }
    public ICommand InspectCommand { get; }
    public ICommand KillAppNetworkCommand { get; }
    public ICommand ClearFeedCommand { get; }
    public ICommand TogglePauseCommand { get; }

    private bool FilterFeed(object o)
    {
        if (o is not FeedEvent e) return false;
        if (_filter == FeedFilter.Blocked && e.Verdict != FeedVerdict.Blocked) return false;
        if (_filter == FeedFilter.Allowed && e.Verdict != FeedVerdict.Allowed) return false;
        return _searchText.Length == 0 || e.SearchKey.Contains(_searchText.Trim().ToLowerInvariant(), StringComparison.Ordinal);
    }

    private void Flush()
    {
        bool any = false;
        while (_pending.TryDequeue(out var e))
        {
            FeedItems.Insert(0, e);
            if (e.Verdict == FeedVerdict.Blocked) _blockedSession++;
            else if (e.Verdict == FeedVerdict.Allowed) _allowedSession++;
            any = true;
        }
        if (!any) return;
        while (FeedItems.Count > MaxFeedItems) FeedItems.RemoveAt(FeedItems.Count - 1);
        OnPropertyChanged(nameof(BlockedSessionText));
        OnPropertyChanged(nameof(AllowedSessionText));
    }

    // ───────────── metrics ─────────────
    private EngineStats Stats
    {
        get => _stats;
        set
        {
            _stats = value;
            OnPropertyChanged(nameof(TelemetryBlockedText));
            OnPropertyChanged(nameof(EtlWipedText));
            OnPropertyChanged(nameof(DnsBlockedText));
            OnPropertyChanged(nameof(DohLatencyText));
            OnPropertyChanged(nameof(FirewallRulesText));
            OnPropertyChanged(nameof(ExeBlockedText));
            OnPropertyChanged(nameof(AvStatusText));
            OnPropertyChanged(nameof(LastScanText));
            OnPropertyChanged(nameof(QuarantineBadge));
            OnPropertyChanged(nameof(EventsPerSecondText));
            Shell.RefreshUpdateWindowLabel();
        }
    }

    public string TelemetryBlockedText => _stats.TelemetryBlocked.ToString("N0");
    public string EtlWipedText => $"{_stats.EtlMegabytesWiped:N1} MB";
    public string DnsBlockedText => _stats.DnsBlocked.ToString("N0");
    public string DohLatencyText => $"{_stats.DohLatencyMs} ms";
    public string FirewallRulesText => _stats.FirewallRules.ToString("N0");
    public string ExeBlockedText => _stats.ExeBlocked.ToString("N0");
    public string AvStatusText => _stats.RealtimeProtection ? "ACTIVE" : "PAUSED";
    public string QuarantineBadge => $"{_stats.QuarantinedCount} QUARANTINED";
    public string EventsPerSecondText => $"{_stats.EventsPerSecond:0.0} ev/s";

    public string LastScanText => _stats.LastScan is not { } t
        ? "never"
        : (DateTime.Now - t) switch
        {
            var d when d.TotalMinutes < 1 => "just now",
            var d when d.TotalHours < 1 => $"{(int)d.TotalMinutes}m ago",
            var d when d.TotalDays < 1 => $"{(int)d.TotalHours}h ago",
            var d => $"{(int)d.TotalDays}d ago",
        };

    public string BlockedSessionText => _blockedSession.ToString("N0");
    public string AllowedSessionText => _allowedSession.ToString("N0");
    public string UptimeText => (DateTime.Now - _sessionStart).ToString(@"hh\:mm\:ss");
}
