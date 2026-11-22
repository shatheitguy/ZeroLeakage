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
using ZeroLeakage.UI.Services.Dns;

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
public sealed class FilterGroupViewModel : ObservableObject
{
    public required string Name { get; init; }
    public ObservableCollection<BlocklistSource> Lists { get; } = new();
    public string CountText => $"{Lists.Count(l => l.IsEnabled)}/{Lists.Count}";
    public void Refresh() => OnPropertyChanged(nameof(CountText));
}

public sealed class DnsTelemetryViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private readonly IProtectionEngine _engine;
    private readonly FilterListService _filters;
    private DohResolver _selectedResolver;
    private string _newDomain = "", _newAllow = "", _newListUrl = "", _newListName = "", _customResolverUrl = "";
    private string _dnssecTestDomain = "cloudflare.com", _dnssecTestResult = "";
    private string? _addListError;
    private double _wipeProgress;
    private bool _isWiping, _dnssecEnabled, _dnssecStrict, _isTestingDnssec;
    private string _lastWipeText = "Not wiped this session";
    private int _latency, _tab;

    public DnsTelemetryViewModel(MainViewModel shell, IProtectionEngine engine)
    {
        _shell = shell;
        _engine = engine;
        _filters = App.Filters;

        foreach (var b in engine.GetBlocklists()) Hook(b);
        RebuildGroups();
        _filters.Lists.CollectionChanged += (_, e) =>
        {
            if (e.NewItems is not null) foreach (BlocklistSource b in e.NewItems) Hook(b);
            RebuildGroups();
        };
        _filters.IndexRebuilt += (_, _) => Ui.Post(() => OnPropertyChanged(nameof(ActiveEntriesText)));

        foreach (var r in engine.GetResolvers()) Resolvers.Add(r);
        foreach (var t in engine.GetTelemetryServices()) TelemetryServices.Add(t);
        _selectedResolver = engine.CurrentResolver;
        _dnssecEnabled = engine.DnssecEnabled;
        _dnssecStrict = engine.DnssecStrict;

        AddDomainCommand = new RelayCommand(() =>
        {
            var d = _filters.Block(NewDomain);
            if (d is null) return;
            NewDomain = "";
            _shell.ShowSnackbar($"Blocked domain {d}");
        }, () => FilterParser.Normalize(NewDomain) is not null);
        RemoveDomainCommand = new RelayCommand(p => { if (p is string d) _filters.RemoveBlock(d); });
        AddAllowCommand = new RelayCommand(() =>
        {
            var d = _filters.Allow(NewAllow);
            if (d is null) return;
            NewAllow = "";
            _shell.ShowSnackbar($"Allowlisted {d}");
        }, () => FilterParser.Normalize(NewAllow) is not null);
        RemoveAllowCommand = new RelayCommand(p => { if (p is string d) _filters.RemoveAllow(d); });

        UpdateAllCommand = new AsyncRelayCommand(async () =>
        {
            _shell.ShowSnackbar("Updating enabled filter lists…");
            await _filters.UpdateAllAsync();
            _shell.ShowSnackbar($"Filters updated · {_filters.TotalRules:N0} rules active");
        });
        UpdateListCommand = new AsyncRelayCommand(async p => { if (p is BlocklistSource l) await _filters.UpdateAsync(l); });
        RemoveListCommand = new AsyncRelayCommand(async p => { if (p is BlocklistSource l) await _filters.RemoveCustomAsync(l); });
        OpenHomepageCommand = new RelayCommand(p =>
        {
            if (p is BlocklistSource { Homepage: { } url }) OpenUrl(url);
        });
        AddListCommand = new AsyncRelayCommand(async () =>
        {
            AddListError = null;
            var err = await _filters.AddCustomAsync(NewListUrl, NewListName);
            if (err is null) { NewListUrl = ""; NewListName = ""; _shell.ShowSnackbar("Filter list added"); }
            else AddListError = err;
        }, () => NewListUrl.Trim().Length > 8);

        UseCustomResolverCommand = new RelayCommand(() =>
        {
            var url = CustomResolverUrl.Trim();
            if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                _shell.ShowSnackbar("DoH endpoints must be https:// URLs");
                return;
            }
            var existing = Resolvers.FirstOrDefault(r => r.IsCustom);
            if (existing is not null) Resolvers.Remove(existing);
            var custom = new DohResolver($"Custom · {uri.Host}", url, "Your own DoH endpoint", "Custom") { IsCustom = true };
            Resolvers.Add(custom);
            SelectedResolver = custom;
        }, () => CustomResolverUrl.Trim().Length > 8);

        TestDnssecCommand = new AsyncRelayCommand(TestDnssecAsync, () => !IsTestingDnssec);
        DownloadGeoCommand = new AsyncRelayCommand(() => Geo.DownloadAsync());
        DeleteGeoCommand = new RelayCommand(() => Geo.Delete());
        WipeLogsCommand = new AsyncRelayCommand(WipeAsync);

        engine.StatsUpdated += (_, s) => Ui.Post(() => Latency = s.DohLatencyMs);
    }

    private void Hook(BlocklistSource b)
    {
        b.PropertyChanged += (s, e) =>
        {
            if (s is not BlocklistSource list) return;
            if (e.PropertyName == nameof(BlocklistSource.IsEnabled))
            {
                if (!_filters.IsRestoring) _ = _engine.SetBlocklistEnabledAsync(list, list.IsEnabled);
                OnPropertyChanged(nameof(ActiveEntriesText));
                RefreshGroupCounts();
            }
        };
    }

    private void RebuildGroups()
    {
        Groups.Clear();
        foreach (var name in FilterListService.GroupOrder)
        {
            var g = new FilterGroupViewModel { Name = name };
            foreach (var l in _filters.Lists.Where(l => l.Group == name)) g.Lists.Add(l);
            if (g.Lists.Count > 0) Groups.Add(g);
        }
    }

    private void RefreshGroupCounts()
    {
        foreach (var g in Groups) g.Refresh();
    }

    public int Tab { get => _tab; set => SetProperty(ref _tab, value); }

    public ObservableCollection<FilterGroupViewModel> Groups { get; } = new();
    public ObservableCollection<DohResolver> Resolvers { get; } = new();
    public ObservableCollection<TelemetryServiceStatus> TelemetryServices { get; } = new();
    public ObservableCollection<string> CustomDomains => _filters.UserBlock;
    public ObservableCollection<string> AllowDomains => _filters.UserAllow;
    public GeoIpService Geo => App.GeoIp;
    public string GeoAttribution => GeoIpService.Attribution;

    public string ActiveEntriesText => $"{_filters.TotalRules:N0} rules · {_filters.Lists.Count(l => l.IsEnabled)} lists";

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

    public string CustomResolverUrl { get => _customResolverUrl; set => SetProperty(ref _customResolverUrl, value ?? ""); }

    public bool DnssecEnabled
    {
        get => _dnssecEnabled;
        set
        {
            if (!SetProperty(ref _dnssecEnabled, value)) return;
            if (!value) DnssecStrict = false;
            _ = _engine.SetDnssecAsync(value, _dnssecStrict);
            _shell.ShowSnackbar(value ? "DNSSEC validation on" : "DNSSEC validation off");
        }
    }

    public bool DnssecStrict
    {
        get => _dnssecStrict;
        set
        {
            if (!SetProperty(ref _dnssecStrict, value && _dnssecEnabled)) return;
            _ = _engine.SetDnssecAsync(_dnssecEnabled, _dnssecStrict);
        }
    }

    public string DnssecTestDomain { get => _dnssecTestDomain; set => SetProperty(ref _dnssecTestDomain, value ?? ""); }
    public string DnssecTestResult { get => _dnssecTestResult; private set => SetProperty(ref _dnssecTestResult, value); }
    public bool IsTestingDnssec { get => _isTestingDnssec; private set => SetProperty(ref _isTestingDnssec, value); }

    public int Latency { get => _latency; private set { if (SetProperty(ref _latency, value)) OnPropertyChanged(nameof(LatencyText)); } }
    public string LatencyText => $"{_latency} ms";

    public string NewDomain { get => _newDomain; set => SetProperty(ref _newDomain, value ?? ""); }
    public string NewAllow { get => _newAllow; set => SetProperty(ref _newAllow, value ?? ""); }
    public string NewListUrl { get => _newListUrl; set => SetProperty(ref _newListUrl, value ?? ""); }
    public string NewListName { get => _newListName; set => SetProperty(ref _newListName, value ?? ""); }
    public string? AddListError { get => _addListError; private set => SetProperty(ref _addListError, value); }

    public ICommand AddDomainCommand { get; }
    public ICommand RemoveDomainCommand { get; }
    public ICommand AddAllowCommand { get; }
    public ICommand RemoveAllowCommand { get; }
    public ICommand UpdateAllCommand { get; }
    public ICommand UpdateListCommand { get; }
    public ICommand RemoveListCommand { get; }
    public ICommand OpenHomepageCommand { get; }
    public ICommand AddListCommand { get; }
    public ICommand UseCustomResolverCommand { get; }
    public ICommand TestDnssecCommand { get; }
    public ICommand DownloadGeoCommand { get; }
    public ICommand DeleteGeoCommand { get; }

    public double WipeProgress { get => _wipeProgress; private set => SetProperty(ref _wipeProgress, value); }
    public bool IsWiping { get => _isWiping; private set => SetProperty(ref _isWiping, value); }
    public string LastWipeText { get => _lastWipeText; private set => SetProperty(ref _lastWipeText, value); }
    public ICommand WipeLogsCommand { get; }

    /// <summary>Kept for callers from the live feed; the domain is already in the shared blocklist.</summary>
    public void AddCustomDomainFromFeed(string domain) { }

    public static void OpenUrl(string url)
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
    }

    private async Task TestDnssecAsync()
    {
        var d = FilterParser.Normalize(DnssecTestDomain);
        if (d is null) { DnssecTestResult = "Enter a domain like cloudflare.com"; return; }
        IsTestingDnssec = true;
        DnssecTestResult = $"Asking {SelectedResolver.Name}…";
        try
        {
            var r = await DohProbe.ResolveAsync(d, 1, SelectedResolver.Name, SelectedResolver.Address, dnssec: true);
            DnssecTestResult = r.Error is not null
                ? $"{d}: lookup failed — {r.Error}"
                : $"{d} → {DnssecLabel(r.Dnssec)} · {DnsWire.RcodeName(r.Rcode)} · flags [{r.ResponseFlags}] · {r.LatencyMs} ms via {r.Resolver}"
                  + (r.Ede is { } ede ? $" · EDE: {DnsWire.EdeName(ede)}" : "");
        }
        finally { IsTestingDnssec = false; }
    }

    public static string DnssecLabel(DnssecStatus s) => s switch
    {
        DnssecStatus.Secure => "DNSSEC validated (AD)",
        DnssecStatus.Insecure => "not DNSSEC-signed",
        DnssecStatus.Bogus => "DNSSEC FAILED (bogus)",
        DnssecStatus.Off => "DNSSEC not requested",
        _ => "not checked",
    };

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
