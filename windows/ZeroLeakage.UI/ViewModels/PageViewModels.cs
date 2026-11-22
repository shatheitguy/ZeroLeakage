using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Data;
using System.Windows.Input;
using Microsoft.Win32;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.Mvvm;
using ZeroLeakage.UI.Services;

namespace ZeroLeakage.UI.ViewModels;

// ═════════════════════════════ Firewall Rules ═════════════════════════════
public sealed class FirewallViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private readonly IProtectionEngine _engine;
    private string _searchText = "";
    private bool _wifiEnabled = true, _lanEnabled = true, _wanEnabled = true;

    public FirewallViewModel(MainViewModel shell, IProtectionEngine engine)
    {
        _shell = shell;
        _engine = engine;
        AppsView = CollectionViewSource.GetDefaultView(Apps);
        AppsView.Filter = o => o is AppRule a && (_searchText.Length == 0
            || a.Name.Contains(_searchText, StringComparison.OrdinalIgnoreCase)
            || a.Path.Contains(_searchText, StringComparison.OrdinalIgnoreCase));

        KillAppCommand = new AsyncRelayCommand(async p =>
        {
            if (p is not AppRule a) return;
            bool kill = !a.IsFullyKilled;
            a.WifiAllowed = a.LanAllowed = a.WanAllowed = !kill;
            if (kill) await _engine.KillAppNetworkAsync(a.Name);
            _shell.ShowSnackbar(kill ? $"{a.Name} cut off from every network" : $"{a.Name} network access restored");
        });
        Refresh();
    }

    public ObservableCollection<AppRule> Apps { get; } = new();
    public ICollectionView AppsView { get; }
    public ICommand KillAppCommand { get; }

    public string SearchText
    {
        get => _searchText;
        set { if (SetProperty(ref _searchText, value ?? "")) AppsView.Refresh(); }
    }

    public bool WifiEnabled { get => _wifiEnabled; set { if (SetProperty(ref _wifiEnabled, value)) Global(NetworkScope.WiFi, value); } }
    public bool LanEnabled { get => _lanEnabled; set { if (SetProperty(ref _lanEnabled, value)) Global(NetworkScope.Lan, value); } }
    public bool WanEnabled { get => _wanEnabled; set { if (SetProperty(ref _wanEnabled, value)) Global(NetworkScope.Wan, value); } }

    public string SummaryText => $"{Apps.Count} apps · {Apps.Count(a => a.IsFullyKilled)} fully killed · {Apps.Sum(a => a.BlockedAttempts):N0} blocked attempts";

    private void Global(NetworkScope scope, bool allowed)
    {
        _ = _engine.SetGlobalScopeAsync(scope, allowed);
        var name = scope switch { NetworkScope.WiFi => "Wi-Fi", NetworkScope.Lan => "LAN", _ => "WAN / Internet" };
        _shell.ShowSnackbar(allowed ? $"{name} kill-switch released" : $"{name} kill-switch engaged — all traffic dropped");
    }

    public void Refresh()
    {
        foreach (var a in Apps) a.PropertyChanged -= OnAppChanged;
        Apps.Clear();
        foreach (var a in _engine.GetAppRules().OrderByDescending(a => a.BlockedAttempts))
        {
            a.PropertyChanged += OnAppChanged;
            Apps.Add(a);
        }
        OnPropertyChanged(nameof(SummaryText));
    }

    public void MarkKilled(string processName)
    {
        var app = Apps.FirstOrDefault(a => a.Name.Equals(processName, StringComparison.OrdinalIgnoreCase));
        if (app is null) return;
        app.WifiAllowed = app.LanAllowed = app.WanAllowed = false;
    }

    private void OnAppChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not AppRule a) return;
        switch (e.PropertyName)
        {
            case nameof(AppRule.WifiAllowed): _ = _engine.SetAppAccessAsync(a, NetworkScope.WiFi, a.WifiAllowed); break;
            case nameof(AppRule.LanAllowed): _ = _engine.SetAppAccessAsync(a, NetworkScope.Lan, a.LanAllowed); break;
            case nameof(AppRule.WanAllowed): _ = _engine.SetAppAccessAsync(a, NetworkScope.Wan, a.WanAllowed); break;
        }
        OnPropertyChanged(nameof(SummaryText));
    }
}

// ═════════════════════════════ DNS & Telemetry ═════════════════════════════
public sealed class DnsTelemetryViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private readonly IProtectionEngine _engine;
    private DohResolver _selectedResolver;
    private string _newDomain = "";
    private double _wipeProgress;
    private bool _isWiping;
    private string _lastWipeText = "Not wiped this session";
    private int _latency;

    public DnsTelemetryViewModel(MainViewModel shell, IProtectionEngine engine)
    {
        _shell = shell;
        _engine = engine;

        foreach (var b in engine.GetBlocklists())
        {
            b.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName != nameof(BlocklistSource.IsEnabled) || s is not BlocklistSource list) return;
                _ = _engine.SetBlocklistEnabledAsync(list, list.IsEnabled);
                OnPropertyChanged(nameof(ActiveEntriesText));
            };
            Blocklists.Add(b);
        }
        foreach (var r in engine.GetResolvers()) Resolvers.Add(r);
        foreach (var t in engine.GetTelemetryServices()) TelemetryServices.Add(t);
        _selectedResolver = Resolvers[0];

        AddDomainCommand = new AsyncRelayCommand(AddDomainAsync, () => NormalizeDomain(NewDomain) is not null);
        RemoveDomainCommand = new AsyncRelayCommand(async p =>
        {
            if (p is not string d) return;
            await _engine.UnblockDomainAsync(d);
            CustomDomains.Remove(d);
        });
        WipeLogsCommand = new AsyncRelayCommand(WipeAsync);

        engine.StatsUpdated += (_, s) => Ui.Post(() => Latency = s.DohLatencyMs);
    }

    public ObservableCollection<BlocklistSource> Blocklists { get; } = new();
    public ObservableCollection<DohResolver> Resolvers { get; } = new();
    public ObservableCollection<TelemetryServiceStatus> TelemetryServices { get; } = new();
    public ObservableCollection<string> CustomDomains { get; } = new();

    public string ActiveEntriesText => $"{Blocklists.Where(b => b.IsEnabled).Sum(b => b.EntryCount):N0} domains enforced";

    public DohResolver SelectedResolver
    {
        get => _selectedResolver;
        set
        {
            if (value is null || !SetProperty(ref _selectedResolver, value)) return;
            _ = _engine.SetResolverAsync(value);
            _shell.ShowSnackbar($"DNS-over-HTTPS → {value.Name}");
        }
    }

    public int Latency { get => _latency; private set { if (SetProperty(ref _latency, value)) OnPropertyChanged(nameof(LatencyText)); } }
    public string LatencyText => $"{_latency} ms";

    public string NewDomain { get => _newDomain; set => SetProperty(ref _newDomain, value ?? ""); }
    public ICommand AddDomainCommand { get; }
    public ICommand RemoveDomainCommand { get; }

    public double WipeProgress { get => _wipeProgress; private set => SetProperty(ref _wipeProgress, value); }
    public bool IsWiping { get => _isWiping; private set => SetProperty(ref _isWiping, value); }
    public string LastWipeText { get => _lastWipeText; private set => SetProperty(ref _lastWipeText, value); }
    public ICommand WipeLogsCommand { get; }

    public void AddCustomDomainFromFeed(string domain)
    {
        if (!CustomDomains.Contains(domain, StringComparer.OrdinalIgnoreCase)) CustomDomains.Insert(0, domain);
    }

    private static string? NormalizeDomain(string raw)
    {
        var d = raw.Trim().ToLowerInvariant();
        if (d.StartsWith("http://")) d = d[7..];
        if (d.StartsWith("https://")) d = d[8..];
        d = d.Split('/')[0];
        return d.Length > 3 && d.Contains('.') && !d.Contains(' ') ? d : null;
    }

    private async Task AddDomainAsync()
    {
        var d = NormalizeDomain(NewDomain);
        if (d is null) return;
        await _engine.BlockDomainAsync(d);
        AddCustomDomainFromFeed(d);
        NewDomain = "";
        _shell.ShowSnackbar($"Blocked domain {d}");
    }

    private async Task WipeAsync()
    {
        IsWiping = true;
        WipeProgress = 0;
        try
        {
            var mb = await _engine.WipeTraceLogsAsync(new Progress<double>(p => WipeProgress = p));
            LastWipeText = $"Wiped {mb:N1} MB of .etl traces at {DateTime.Now:HH:mm}";
            _shell.ShowSnackbar($"Trace logs wiped · {mb:N1} MB purged");
        }
        finally { IsWiping = false; }
    }
}

// ═════════════════════════════ DeepScan AV ═════════════════════════════
public sealed class DeepScanViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private readonly IProtectionEngine _engine;
    private CancellationTokenSource? _cts;
    private bool _isScanning, _realtimeEnabled = true;
    private double _progress;
    private string _currentPath = "";
    private long _filesScanned;
    private int _threatsFound;
    private string _statusText = "Idle — last scan clean";
    private ScanKind _kind;

    public DeepScanViewModel(MainViewModel shell, IProtectionEngine engine)
    {
        _shell = shell;
        _engine = engine;
        QuickScanCommand = new AsyncRelayCommand(() => ScanAsync(ScanKind.Quick), () => !IsScanning);
        FullScanCommand = new AsyncRelayCommand(() => ScanAsync(ScanKind.Full), () => !IsScanning);
        CancelScanCommand = new RelayCommand(() => _cts?.Cancel(), () => IsScanning);
        RestoreItemCommand = new RelayCommand(p =>
        {
            if (p is not QuarantineItem q) return;
            _shell.RequestConfirm("Restore from vault?",
                $"{q.FileName} was flagged as {q.ThreatName}. Restoring puts it back at {q.OriginalPath} and it will be able to run.",
                "Restore file", true, async () =>
                {
                    await _engine.RestoreQuarantinedAsync(q);
                    Quarantine.Remove(q);
                    _shell.ShowSnackbar($"{q.FileName} restored");
                });
        });
        DeleteItemCommand = new RelayCommand(p =>
        {
            if (p is not QuarantineItem q) return;
            _shell.RequestConfirm("Delete permanently?",
                $"{q.FileName} will be shredded from the encrypted vault. This cannot be undone.",
                "Delete forever", true, async () =>
                {
                    await _engine.DeleteQuarantinedAsync(q);
                    Quarantine.Remove(q);
                    _shell.ShowSnackbar($"{q.FileName} destroyed");
                });
        });
        Refresh();
    }

    public ObservableCollection<QuarantineItem> Quarantine { get; } = new();
    public ICommand QuickScanCommand { get; }
    public ICommand FullScanCommand { get; }
    public ICommand CancelScanCommand { get; }
    public ICommand RestoreItemCommand { get; }
    public ICommand DeleteItemCommand { get; }

    public bool IsScanning { get => _isScanning; private set => SetProperty(ref _isScanning, value); }
    public double Progress { get => _progress; private set { if (SetProperty(ref _progress, value)) OnPropertyChanged(nameof(ProgressText)); } }
    public string ProgressText => $"{_progress:0}%";
    public string CurrentPath { get => _currentPath; private set => SetProperty(ref _currentPath, value); }
    public long FilesScanned { get => _filesScanned; private set { if (SetProperty(ref _filesScanned, value)) OnPropertyChanged(nameof(FilesScannedText)); } }
    public string FilesScannedText => _filesScanned.ToString("N0");
    public int ThreatsFound { get => _threatsFound; private set => SetProperty(ref _threatsFound, value); }
    public string StatusText { get => _statusText; private set => SetProperty(ref _statusText, value); }
    public string ScanKindText => _kind == ScanKind.Quick ? "QUICK SCAN" : "FULL SCAN";

    public bool RealtimeEnabled
    {
        get => _realtimeEnabled;
        set
        {
            if (!SetProperty(ref _realtimeEnabled, value)) return;
            _ = _engine.SetRealtimeProtectionAsync(value);
            _shell.ShowSnackbar(value ? "Real-time shield on" : "Real-time shield paused");
        }
    }

    public void Refresh()
    {
        Quarantine.Clear();
        foreach (var q in _engine.GetQuarantine()) Quarantine.Add(q);
    }

    private async Task ScanAsync(ScanKind kind)
    {
        _kind = kind;
        OnPropertyChanged(nameof(ScanKindText));
        _cts = new CancellationTokenSource();
        IsScanning = true;
        Progress = 0;
        ThreatsFound = 0;
        FilesScanned = 0;
        StatusText = kind == ScanKind.Quick ? "Quick scan — memory, startup & downloads" : "Full scan — every fixed drive";
        try
        {
            var result = await _engine.RunScanAsync(kind, new Progress<ScanProgress>(p =>
            {
                Progress = p.Percent;
                CurrentPath = p.CurrentPath;
                FilesScanned = p.FilesScanned;
                ThreatsFound = p.ThreatsFound;
            }), _cts.Token);
            StatusText = result.ThreatsFound == 0
                ? $"Clean · {result.FilesScanned:N0} files in {result.Duration:mm\\:ss}"
                : $"{result.ThreatsFound} threat(s) moved to the encrypted vault";
            CurrentPath = "";
            Refresh();
            _shell.ShowSnackbar(StatusText);
        }
        catch (OperationCanceledException)
        {
            StatusText = "Scan cancelled";
            CurrentPath = "";
        }
        finally
        {
            IsScanning = false;
            _cts.Dispose();
            _cts = null;
        }
    }
}

// ═════════════════════════════ Snapshots & Settings ═════════════════════════════
public sealed class SettingsViewModel : ObservableObject
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private readonly MainViewModel _shell;
    private readonly IProtectionEngine _engine;
    private readonly UiSettings _settings;
    private string _newSnapshotName = "";
    private bool _isCreating;

    public SettingsViewModel(MainViewModel shell, IProtectionEngine engine, UiSettings settings)
    {
        _shell = shell;
        _engine = engine;
        _settings = settings;
        foreach (var s in engine.GetSnapshots()) Snapshots.Add(s);

        CreateSnapshotCommand = new AsyncRelayCommand(async () =>
        {
            IsCreating = true;
            try
            {
                var s = await _engine.CreateSnapshotAsync(NewSnapshotName);
                Snapshots.Insert(0, s);
                NewSnapshotName = "";
                _shell.ShowSnackbar($"Snapshot \"{s.Name}\" saved");
            }
            finally { IsCreating = false; }
        });
        RestoreSnapshotCommand = new RelayCommand(p =>
        {
            if (p is not SystemSnapshot s) return;
            _shell.RequestConfirm("Roll back to snapshot?",
                $"Firewall rules, DNS settings, services and registry policies return to \"{s.Name}\" ({s.DateText}). Current settings are replaced.",
                "Roll back", true, async () =>
                {
                    await _engine.RestoreSnapshotAsync(s);
                    _shell.Firewall.Refresh();
                    _shell.ShowSnackbar($"Rolled back to \"{s.Name}\"");
                });
        });
        RerunAuditCommand = new RelayCommand(() => _shell.Wizard.Open());
    }

    public ObservableCollection<SystemSnapshot> Snapshots { get; } = new();
    public ICommand CreateSnapshotCommand { get; }
    public ICommand RestoreSnapshotCommand { get; }
    public ICommand RerunAuditCommand { get; }
    public ICommand RestoreDefaultsCommand => _shell.RestoreDefaultsCommand;

    public string NewSnapshotName { get => _newSnapshotName; set => SetProperty(ref _newSnapshotName, value ?? ""); }
    public bool IsCreating { get => _isCreating; private set => SetProperty(ref _isCreating, value); }

    public int UpdateWindowMinutes
    {
        get => _settings.UpdateWindowMinutes;
        set
        {
            if (_settings.UpdateWindowMinutes == value) return;
            _settings.UpdateWindowMinutes = value;
            Save();
            _shell.RefreshUpdateWindowLabel();
        }
    }

    public bool MinimizeToTray { get => _settings.MinimizeToTray; set { _settings.MinimizeToTray = value; Save(); } }
    public bool AutoUpdateDefinitions { get => _settings.AutoUpdateDefinitions; set { _settings.AutoUpdateDefinitions = value; Save(); } }

    public bool StartWithWindows
    {
        get => _settings.StartWithWindows;
        set
        {
            _settings.StartWithWindows = value;
            Save();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
                if (key is null) return;
                var exe = Environment.ProcessPath;
                if (value && exe is not null) key.SetValue("ZeroLeakage", $"\"{exe}\" --tray");
                else key.DeleteValue("ZeroLeakage", throwOnMissingValue: false);
            }
            catch (Exception ex) { _shell.ShowSnackbar($"Could not update startup entry: {ex.Message}"); }
        }
    }

    private void Save([System.Runtime.CompilerServices.CallerMemberName] string? name = null)
    {
        UiSettingsStore.Save(_settings);
        OnPropertyChanged(name);
    }
}
