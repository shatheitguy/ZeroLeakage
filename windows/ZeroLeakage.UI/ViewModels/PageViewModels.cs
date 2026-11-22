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

// ═════════════════════════════ DeepScan AV (Microsoft Defender) ═════════════════════════════
/// <summary>
/// DeepScan is a front end for the Microsoft Defender engine built into Windows: real scans, real detections,
/// real quarantine. Removing or restoring a threat asks for administrator rights.
/// </summary>
public sealed class DeepScanViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private CancellationTokenSource? _cts;
    private bool _isScanning, _isLoading;
    private TimeSpan _elapsed;
    private bool _isUpdatingDefinitions;
    private string? _definitionsStatus;
    private int _threatsFound;
    private string _statusText = "Checking Microsoft Defender…";
    private ScanKind _kind;
    private DefenderStatus? _status;

    public DeepScanViewModel(MainViewModel shell, IProtectionEngine engine)
    {
        _shell = shell;
        QuickScanCommand = new AsyncRelayCommand(() => ScanAsync(ScanKind.Quick), () => !IsScanning && DefenderAvailable);
        FullScanCommand = new AsyncRelayCommand(() => ScanAsync(ScanKind.Full), () => !IsScanning && DefenderAvailable);
        CancelScanCommand = new RelayCommand(() => _cts?.Cancel(), () => IsScanning);
        RefreshCommand = new AsyncRelayCommand(LoadAsync, () => !_isLoading);
        UpdateDefinitionsCommand = new AsyncRelayCommand(UpdateDefinitionsAsync, () => !IsUpdatingDefinitions && !IsScanning && DefenderAvailable);
        OpenSecurityCommand = new RelayCommand(() => DefenderService.OpenWindowsSecurity("threat"));
        OpenRealtimeSettingsCommand = new RelayCommand(() => DefenderService.OpenWindowsSecurity("threatsettings"));
        RemoveThreatsCommand = new RelayCommand(() =>
            _shell.RequestConfirm("Remove active threats?",
                "Microsoft Defender will remove every active threat it has detected. Windows will ask for administrator permission.",
                "Remove threats", true, async () =>
                {
                    bool ok = await DefenderService.RemoveActiveThreatsAsync();
                    await LoadAsync();
                    _shell.ShowSnackbar(ok ? "Defender removed the active threats" : "Not removed: permission was declined or Defender reported an error");
                }));
        RestoreItemCommand = new RelayCommand(p =>
        {
            if (p is not DefenderDetection d) return;
            _shell.RequestConfirm("Restore from quarantine?",
                $"{d.FileName} was flagged by Microsoft Defender as {d.ThreatName}. Restoring puts it back at {d.PrimaryResource} and it will be able to run. Windows will ask for administrator permission.",
                "Restore file", true, async () =>
                {
                    bool ok = await DefenderService.RestoreAsync(d);
                    await LoadAsync();
                    _shell.ShowSnackbar(ok ? $"{d.FileName} restored by Defender" : "Not restored: permission was declined or Defender reported an error");
                });
        });
        _ = LoadAsync();
    }

    public ObservableCollection<DefenderDetection> Detections { get; } = new();
    public ICommand QuickScanCommand { get; }
    public ICommand FullScanCommand { get; }
    public ICommand CancelScanCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand UpdateDefinitionsCommand { get; }
    public ICommand RemoveThreatsCommand { get; }
    public ICommand RestoreItemCommand { get; }
    public ICommand OpenSecurityCommand { get; }
    public ICommand OpenRealtimeSettingsCommand { get; }

    public bool IsScanning
    {
        get => _isScanning;
        private set { if (SetProperty(ref _isScanning, value)) { OnPropertyChanged(nameof(ProgressText)); CommandManager.InvalidateRequerySuggested(); } }
    }
    /// <summary>Elapsed time while scanning (Defender does not publish a percentage); a check mark when idle.</summary>
    public string ProgressText => IsScanning ? _elapsed.ToString(_elapsed.TotalHours >= 1 ? @"h\:mm\:ss" : @"mm\:ss") : (ActiveThreats > 0 ? "!" : "✓");
    public int ThreatsFound { get => _threatsFound; private set => SetProperty(ref _threatsFound, value); }
    public string StatusText { get => _statusText; private set => SetProperty(ref _statusText, value); }
    public string ScanKindText => IsScanning ? (_kind == ScanKind.Quick ? "QUICK SCAN" : "FULL SCAN") : (ActiveThreats > 0 ? "ACTION NEEDED" : "PROTECTED");

    public bool DefenderAvailable => _status?.Available == true;
    public bool RealtimeOn => _status?.RealTimeProtection == true;
    public string RealtimeText => _status is null ? "…" : !_status.Available ? "UNAVAILABLE" : _status.RealTimeProtection ? "ON" : "OFF";
    public string SignatureText => _status?.SignaturesUpdated is { } t ? $"{_status.SignatureVersion} · {t.ToLocalTime():dd MMM HH:mm}" : "—";
    public string SignatureVersionText => string.IsNullOrEmpty(_status?.SignatureVersion) ? "—" : _status!.SignatureVersion;
    public string SignatureAgeText => _status?.SignaturesUpdated is { } t ? $"Updated {Ago(t.ToLocalTime())}" : "Not updated yet";
    public bool SignaturesStale => _status?.SignaturesUpdated is { } t && DateTime.UtcNow - t.ToUniversalTime() > TimeSpan.FromDays(3);

    public bool IsUpdatingDefinitions
    {
        get => _isUpdatingDefinitions;
        private set { if (SetProperty(ref _isUpdatingDefinitions, value)) CommandManager.InvalidateRequerySuggested(); }
    }
    /// <summary>Result line of the last definitions update (null until the user runs one).</summary>
    public string? DefinitionsStatus { get => _definitionsStatus; private set => SetProperty(ref _definitionsStatus, value); }

    private static string Ago(DateTime local)
    {
        var d = DateTime.Now - local;
        if (d < TimeSpan.FromMinutes(1)) return "just now";
        if (d < TimeSpan.FromHours(1)) return $"{(int)d.TotalMinutes} min ago";
        if (d < TimeSpan.FromDays(1)) return $"{(int)d.TotalHours} h ago";
        return local.ToString("dd MMM · HH:mm");
    }

    public string LastScanText => _status?.LastScan is { } t ? t.ToLocalTime().ToString("dd MMM yyyy · HH:mm") : "Never";
    public int ActiveThreats => Detections.Count(d => d.NeedsAction);
    public bool HasActiveThreats => ActiveThreats > 0;

    /// <summary>Called when the page is opened.</summary>
    public void Refresh() => _ = LoadAsync();

    private async Task LoadAsync()
    {
        if (_isLoading) return;
        _isLoading = true;
        try
        {
            var status = await DefenderService.GetStatusAsync();
            var detections = status.Available ? await DefenderService.GetDetectionsAsync() : Array.Empty<DefenderDetection>();
            _status = status;
            Detections.Clear();
            foreach (var d in detections) Detections.Add(d);
            if (!IsScanning)
            {
                StatusText = !status.Available
                    ? $"Microsoft Defender is unavailable: {status.Error}"
                    : HasActiveThreats ? $"{ActiveThreats} active threat(s) need attention"
                    : "No active threats · protected by Microsoft Defender";
            }
            foreach (var n in new[] { nameof(DefenderAvailable), nameof(RealtimeOn), nameof(RealtimeText), nameof(SignatureText),
                                      nameof(SignatureVersionText), nameof(SignatureAgeText), nameof(SignaturesStale),
                                      nameof(LastScanText), nameof(ActiveThreats), nameof(HasActiveThreats), nameof(ProgressText), nameof(ScanKindText) })
                OnPropertyChanged(n);
            CommandManager.InvalidateRequerySuggested();
        }
        finally { _isLoading = false; }
    }

    /// <summary>Fetches the latest Microsoft Defender security intelligence (may ask for admin if Defender insists).</summary>
    private async Task UpdateDefinitionsAsync()
    {
        IsUpdatingDefinitions = true;
        DefinitionsStatus = "Downloading the latest Microsoft Defender definitions…";
        try
        {
            var outcome = await DefenderService.UpdateSignaturesAsync();
            DefinitionsStatus = outcome.Message;
            _shell.ShowSnackbar(outcome.Message);
        }
        finally
        {
            IsUpdatingDefinitions = false;
            await LoadAsync();
        }
    }

    private async Task ScanAsync(ScanKind kind)
    {
        _kind = kind;
        _cts = new CancellationTokenSource();
        _elapsed = TimeSpan.Zero;
        ThreatsFound = 0;
        IsScanning = true;
        OnPropertyChanged(nameof(ScanKindText));
        StatusText = kind == ScanKind.Quick
            ? "Microsoft Defender quick scan: memory, startup items and common malware locations…"
            : "Microsoft Defender full scan: every file on every fixed drive. This can take an hour or more…";
        string? finalStatus = null;
        try
        {
            var outcome = await DefenderService.ScanAsync(kind == ScanKind.Full, new Progress<TimeSpan>(t =>
            {
                _elapsed = t;
                OnPropertyChanged(nameof(ProgressText));
            }), _cts.Token);
            ThreatsFound = outcome.NewDetections.Count;
            finalStatus = !outcome.Completed ? outcome.Message
                : outcome.NewDetections.Count == 0 ? $"Clean · Defender found no threats ({outcome.Duration:mm\\:ss})"
                : $"Defender found {outcome.NewDetections.Count} threat(s): see the list";
            _shell.ShowSnackbar(finalStatus);
        }
        catch (OperationCanceledException)
        {
            finalStatus = "Scan cancelled";
        }
        catch (Exception ex)
        {
            finalStatus = $"Scan failed: {ex.Message}";
            throw;   // still reported (snackbar + error log)
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            await LoadAsync();
            if (finalStatus is not null) StatusText = finalStatus;
            IsScanning = false;
            OnPropertyChanged(nameof(ScanKindText));
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
    public UpdatesViewModel Updates => _shell.Updates;
    public ICommand OpenAboutCommand => _shell.OpenAboutCommand;

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
