using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Windows.Threading;
using ZeroLeakage.Shared.Ipc;
using ZeroLeakage.UI.Mvvm;
using ZeroLeakage.UI.Services;

namespace ZeroLeakage.UI.ViewModels;

public sealed class GuardFeedItem : ObservableObject
{
    private readonly Action<GuardFeedItem, bool> _toggle;
    private bool _isEnabled;
    private string _statusText = "", _description = "", _name = "";
    private string? _error;

    public GuardFeedItem(string id, Action<GuardFeedItem, bool> toggle)
    {
        Id = id;
        _toggle = toggle;
    }

    public string Id { get; }
    public bool IsServer { get; set; }
    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public string Description { get => _description; set => SetProperty(ref _description, value); }
    public string StatusText { get => _statusText; set => SetProperty(ref _statusText, value); }
    public string? Error { get => _error; set => SetProperty(ref _error, value); }

    public bool IsEnabled
    {
        get => _isEnabled;
        set { if (SetProperty(ref _isEnabled, value)) _toggle(this, value); }
    }

    /// <summary>Refresh from the service without sending a change back.</summary>
    public void Set(bool enabled)
    {
        if (_isEnabled == enabled) return;
        _isEnabled = enabled;
        OnPropertyChanged(nameof(IsEnabled));
    }
}

public sealed record GuardBanItem(string Value, string Reason, string Scenario, string ExpiresText, string CreatedText);

public sealed record GuardAlertItem(string TimeText, string Value, string Scenario, string Message, bool Banned);

/// <summary>
/// Guard page: everything shown comes from the ZeroLeakage Core service over the named pipe. When the service
/// isn't installed or running (dev builds) the page says so and disables its controls — it never shows made-up data.
/// </summary>
public sealed class GuardViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private readonly DispatcherTimer _poll;
    private bool _active, _refreshing, _guardEnabled, _updating, _waitingForUpdate;
    private CoreServiceState _state = CoreServiceState.Unknown;
    private GuardStatusDto? _status;
    private string _banInput = "", _allowInput = "", _serverUrl = "", _lastBansKey = "", _lastAlertsKey = "";

    public GuardViewModel(MainViewModel shell)
    {
        _shell = shell;
        _poll = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _poll.Tick += async (_, _) => await RefreshAsync();
        _poll.Start();

        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        UpdateFeedsCommand = new AsyncRelayCommand(UpdateFeedsAsync, () => IsConnected && !IsUpdatingFeeds);
        BanCommand = new AsyncRelayCommand(() => SendAsync(new CoreRequest { Command = CoreCommands.Ban, Value = BanInput.Trim() },
            () => BanInput = ""), () => IsConnected && BanInput.Trim().Length > 0);
        AllowCommand = new AsyncRelayCommand(() => SendAsync(new CoreRequest { Command = CoreCommands.Allow, Value = AllowInput.Trim() },
            () => AllowInput = ""), () => IsConnected && AllowInput.Trim().Length > 0);
        UnbanCommand = new AsyncRelayCommand(p => p is GuardBanItem b
            ? SendAsync(new CoreRequest { Command = CoreCommands.Unban, Value = b.Value })
            : Task.CompletedTask, _ => IsConnected);
        RemoveAllowCommand = new AsyncRelayCommand(p => p is string v
            ? SendAsync(new CoreRequest { Command = CoreCommands.RemoveAllow, Value = v })
            : Task.CompletedTask, _ => IsConnected);
        SaveServerCommand = new AsyncRelayCommand(SaveServerAsync, () => IsConnected && !IsServerLinked);
        ClearServerCommand = new AsyncRelayCommand(() => SendAsync(new CoreRequest { Command = CoreCommands.SetServer, ServerUrl = "" }),
            () => IsConnected && !IsServerLinked && (_status?.Server.Configured ?? false));

        // First look right away (the dashboard strip shows this), then every 15 s (3 s while the page is open).
        System.Windows.Application.Current?.Dispatcher.BeginInvoke(new Action(() => _ = RefreshAsync()), DispatcherPriority.Background);
    }

    // ───────────── lifecycle ─────────────
    public void Activate()
    {
        _active = true;
        _poll.Interval = TimeSpan.FromSeconds(3);
        _ = RefreshAsync();
    }

    public void Deactivate()
    {
        _active = false;
        _poll.Interval = TimeSpan.FromSeconds(15);
    }

    // ───────────── connection ─────────────
    public CoreServiceState ServiceState { get => _state; private set { if (SetProperty(ref _state, value)) RaiseState(); } }
    public bool IsConnected => _status is not null;
    public bool IsUnavailable => !IsConnected;

    public string ServiceStateText => IsConnected ? "Running" : _state switch
    {
        CoreServiceState.NotInstalled => "Not installed",
        CoreServiceState.Stopped => "Stopped",
        CoreServiceState.Starting => "Starting…",
        CoreServiceState.Stopping => "Stopping…",
        CoreServiceState.Running => "Not responding",
        CoreServiceState.Paused => "Paused",
        _ => "Unknown",
    };

    public string UnavailableTitle => _state switch
    {
        CoreServiceState.NotInstalled => "The ZeroLeakage Core service isn't installed",
        CoreServiceState.Running => "The ZeroLeakage Core service isn't answering",
        CoreServiceState.Starting => "The ZeroLeakage Core service is starting…",
        _ => "The ZeroLeakage Core service isn't running",
    };

    public string UnavailableText => _state switch
    {
        CoreServiceState.NotInstalled =>
            "Guard runs inside the ZeroLeakage Core Windows service, which the ZeroLeakage installer (MSI) sets up. This copy of the app was started without it (a development build?), so Guard is off and nothing on this page is live.",
        CoreServiceState.Running => "The service is running but didn't reply on its local pipe. It may still be loading; this page retries every few seconds.",
        _ => "Start it from Windows Services (services.msc → ZeroLeakage Core), or reinstall ZeroLeakage. Until then Guard isn't blocking anything and this page shows no data.",
    };

    // ───────────── status card ─────────────
    public bool GuardEnabled
    {
        get => _guardEnabled;
        set
        {
            if (!SetProperty(ref _guardEnabled, value)) return;
            _ = SendAsync(new CoreRequest { Command = CoreCommands.SetEnabled, Enabled = value });
        }
    }

    public bool CanToggleGuard => IsConnected && !IsPolicyManaged;
    public bool IsPolicyManaged => _status?.Server.PolicyManaged ?? false;
    public string ManagedBadge => $"MANAGED BY {(_status?.Server.ServerName ?? "SERVER").ToUpperInvariant()}";

    public bool IsUpdatingFeeds => _updating;
    public string LastFeedUpdateText => _status?.LastFeedUpdate is { } t ? Ago(t) : IsConnected ? "never" : "—";
    public string BlockedCountText => IsConnected ? _status!.BlockedEntries.ToString("N0") : "—";
    public string BlockedAddressesText => IsConnected ? $"{FormatCount(_status!.BlockedIPv4Addresses)} IPv4 addresses covered" : "service not running";
    public string FirewallRulesText => IsConnected ? _status!.FirewallRules.ToString("N0") : "—";
    public string ActiveBansText => IsConnected ? _status!.ActiveBans.ToString("N0") : "—";
    public string? Warning => _status switch
    {
        null => null,
        { LastError: { } e } => e,
        { FirewallEnabled: false } => "Windows Defender Firewall is off for the current network, so Guard's rules aren't enforced.",
        { Enabled: false } => "Guard is off: no threat-IP rules are in Windows Firewall.",
        _ => null,
    };

    // dashboard strip
    public string DashboardTitle => IsConnected ? (_status!.Enabled ? "Guard active" : "Guard off") : "Guard unavailable";
    public string DashboardText => IsConnected
        ? $"{_status!.BlockedEntries:N0} threat ranges blocked · {_status.ActiveBans} active ban{(_status.ActiveBans == 1 ? "" : "s")} · {_status.FirewallRules} firewall rules · feeds {LastFeedUpdateText}"
        : ServiceState == CoreServiceState.NotInstalled
            ? "ZeroLeakage Core service not installed — threat-IP blocking is off"
            : "ZeroLeakage Core service not running — threat-IP blocking is off";

    // ───────────── feeds, scenarios, lists ─────────────
    public ObservableCollection<GuardFeedItem> Feeds { get; } = new();
    public ObservableCollection<GuardFeedItem> Scenarios { get; } = new();
    public ObservableCollection<GuardBanItem> Bans { get; } = new();
    public ObservableCollection<GuardAlertItem> Alerts { get; } = new();
    public ObservableCollection<string> Allowlist { get; } = new();

    public string BanInput { get => _banInput; set => SetProperty(ref _banInput, value ?? ""); }
    public string AllowInput { get => _allowInput; set => SetProperty(ref _allowInput, value ?? ""); }

    // ───────────── server bouncer ─────────────
    public string ServerUrl { get => _serverUrl; set => SetProperty(ref _serverUrl, value ?? ""); }
    /// <summary>Set from the view's PasswordBox; never read back from the service.</summary>
    public string ServerKey { get; set; } = "";
    public bool IsServerLinked => _status?.Server.Linked ?? false;
    public bool CanEditServer => IsConnected && !IsServerLinked;
    public string ServerStatusText => _status?.Server switch
    {
        null => "—",
        { Linked: true } s => $"Linked through Account & sync · {s.ServerName} · uses this device's token",
        { Configured: true } s => $"Bouncer key saved for {s.Url}",
        _ => "Off — Guard uses only the public feeds above",
    };

    public ICommand RefreshCommand { get; }
    public ICommand UpdateFeedsCommand { get; }
    public ICommand BanCommand { get; }
    public ICommand AllowCommand { get; }
    public ICommand UnbanCommand { get; }
    public ICommand RemoveAllowCommand { get; }
    public ICommand SaveServerCommand { get; }
    public ICommand ClearServerCommand { get; }

    // ───────────── refresh ─────────────
    public async Task RefreshAsync()
    {
        if (_refreshing) return;
        _refreshing = true;
        try
        {
            var state = await Task.Run(CoreServiceClient.QueryState);
            ServiceState = state;
            var status = state == CoreServiceState.Running
                ? await CoreServiceClient.TrySendAsync(new CoreRequest { Command = CoreCommands.Status })
                : null;
            CoreResponse? lists = null;
            if (status is { Ok: true } && _active)
                lists = await CoreServiceClient.TrySendAsync(new CoreRequest { Command = CoreCommands.Decisions });
            Apply(status is { Ok: true } ? status.Status : null, lists is { Ok: true } ? lists : null);
        }
        finally { _refreshing = false; }
    }

    private void Apply(GuardStatusDto? s, CoreResponse? lists)
    {
        bool wasConnected = IsConnected;
        _status = s;
        if (s is null)
        {
            // Never show stale or made-up data when the service is gone.
            Feeds.Clear(); Scenarios.Clear(); Bans.Clear(); Alerts.Clear(); Allowlist.Clear();
            _lastBansKey = _lastAlertsKey = "";
            _updating = false;
        }
        else
        {
            if (_guardEnabled != s.Enabled) { _guardEnabled = s.Enabled; OnPropertyChanged(nameof(GuardEnabled)); }
            Sync(Feeds, s.Feeds.Select(f => (f.Id, f.Name, f.Description, f.Enabled, f.IsServer,
                Status: f.LastUpdated is { } t ? $"{f.Entries:N0} entries · updated {Ago(t)}" : f.Enabled ? "not downloaded yet" : "off",
                f.LastError)), ToggleFeed);
            Sync(Scenarios, s.Scenarios.Select(c => (c.Id, c.Name, c.Description, c.Enabled, false,
                Status: c.Available ? (c.Note ?? "ready") : (c.Note ?? "unavailable"), Error: c.Available ? null : c.Note)), ToggleScenario);
            _updating = s.UpdatingFeeds;
            if (_waitingForUpdate && !s.UpdatingFeeds)
            {
                _waitingForUpdate = false;
                _shell.ShowSnackbar($"Threat feeds updated · {s.BlockedEntries:N0} ranges blocked");
            }
            if (lists is not null)
            {
                var bans = lists.Decisions ?? new();
                var key = string.Join("|", bans.Select(b => b.Id + b.ExpiresAt));
                if (key != _lastBansKey)
                {
                    _lastBansKey = key;
                    Bans.Clear();
                    foreach (var b in bans)
                        Bans.Add(new GuardBanItem(b.Value, b.Reason, ScenarioLabel(b.Scenario),
                            b.ExpiresAt is { } e ? "expires " + Until(e) : "permanent", Ago(b.CreatedAt)));
                }
                var alerts = lists.Alerts ?? new();
                var akey = string.Join("|", alerts.Select(a => a.Id));
                if (akey != _lastAlertsKey)
                {
                    _lastAlertsKey = akey;
                    Alerts.Clear();
                    foreach (var a in alerts.Take(50))
                        Alerts.Add(new GuardAlertItem(a.Time.ToLocalTime().ToString("dd MMM HH:mm"), a.Value, ScenarioLabel(a.Scenario), a.Message, a.Banned));
                }
                if (!Allowlist.SequenceEqual(lists.Allowlist ?? new()))
                {
                    Allowlist.Clear();
                    foreach (var a in lists.Allowlist ?? new()) Allowlist.Add(a);
                }
            }
            if (!wasConnected && s.Server is { Configured: true, Linked: false, Url: { } u }) ServerUrl = u;
        }
        RaiseState();
        if (wasConnected != IsConnected) CommandManager.InvalidateRequerySuggested();
    }

    private static void Sync(ObservableCollection<GuardFeedItem> target,
        IEnumerable<(string Id, string Name, string Description, bool Enabled, bool IsServer, string Status, string? Error)> items,
        Action<GuardFeedItem, bool> toggle)
    {
        var list = items.ToList();
        if (!target.Select(t => t.Id).SequenceEqual(list.Select(l => l.Id)))
        {
            target.Clear();
            foreach (var i in list) target.Add(new GuardFeedItem(i.Id, toggle));
        }
        for (int k = 0; k < list.Count; k++)
        {
            var (_, name, desc, enabled, isServer, status, error) = list[k];
            var t = target[k];
            t.Name = name; t.Description = desc; t.StatusText = status; t.Error = error; t.IsServer = isServer;
            t.Set(enabled);
        }
    }

    private void ToggleFeed(GuardFeedItem f, bool on) =>
        _ = SendAsync(new CoreRequest { Command = CoreCommands.SetFeed, Target = f.Id, Enabled = on });

    private void ToggleScenario(GuardFeedItem s, bool on) =>
        _ = SendAsync(new CoreRequest { Command = CoreCommands.SetScenario, Target = s.Id, Enabled = on });

    private async Task UpdateFeedsAsync()
    {
        var r = await CoreServiceClient.TrySendAsync(new CoreRequest { Command = CoreCommands.UpdateFeeds });
        if (r is null) { _shell.ShowSnackbar("ZeroLeakage Core didn't answer"); return; }
        _waitingForUpdate = r.Ok;
        _updating = r.Ok;
        OnPropertyChanged(nameof(IsUpdatingFeeds));
        _shell.ShowSnackbar(r.Ok ? r.Message ?? "Updating threat feeds…" : r.Error ?? "Update failed");
    }

    private async Task SaveServerAsync()
    {
        var key = ServerKey;
        await SendAsync(new CoreRequest { Command = CoreCommands.SetServer, ServerUrl = ServerUrl.Trim(), ApiKey = key.Length == 0 ? null : key });
        ServerKey = "";
        OnPropertyChanged(nameof(ServerKey));
    }

    private async Task SendAsync(CoreRequest req, Action? onOk = null)
    {
        var r = await CoreServiceClient.TrySendAsync(req, TimeSpan.FromSeconds(10));
        if (r is null) _shell.ShowSnackbar("ZeroLeakage Core isn't running — nothing was changed");
        else if (!r.Ok) _shell.ShowSnackbar(r.Error ?? "Guard refused that change");
        else
        {
            onOk?.Invoke();
            if (r.Message is { Length: > 0 } m) _shell.ShowSnackbar(m);
        }
        await RefreshAsync();
    }

    private void RaiseState()
    {
        foreach (var p in new[]
                 {
                     nameof(IsConnected), nameof(IsUnavailable), nameof(ServiceStateText), nameof(UnavailableTitle), nameof(UnavailableText),
                     nameof(CanToggleGuard), nameof(IsPolicyManaged), nameof(ManagedBadge), nameof(IsUpdatingFeeds), nameof(LastFeedUpdateText),
                     nameof(BlockedCountText), nameof(BlockedAddressesText), nameof(FirewallRulesText), nameof(ActiveBansText), nameof(Warning),
                     nameof(DashboardTitle), nameof(DashboardText), nameof(IsServerLinked), nameof(CanEditServer), nameof(ServerStatusText),
                 })
            OnPropertyChanged(p);
    }

    private static string ScenarioLabel(string s) => s switch
    {
        "brute-force" => "Brute force",
        "port-scan" => "Port scan",
        "manual" => "Manual",
        _ => s,
    };

    private static string FormatCount(long n) => n switch
    {
        >= 1_000_000_000 => $"{n / 1e9:0.#}B",
        >= 1_000_000 => $"{n / 1e6:0.#}M",
        >= 10_000 => $"{n / 1e3:0}K",
        _ => n.ToString("N0"),
    };

    private static string Ago(DateTimeOffset t)
    {
        var d = DateTimeOffset.Now - t;
        if (d.TotalMinutes < 1) return "just now";
        if (d.TotalHours < 1) return $"{(int)d.TotalMinutes} min ago";
        if (d.TotalDays < 1) return $"{(int)d.TotalHours} h ago";
        return $"{(int)d.TotalDays} d ago";
    }

    private static string Until(DateTimeOffset t)
    {
        var d = t - DateTimeOffset.Now;
        if (d.TotalMinutes < 1) return "now";
        if (d.TotalHours < 1) return $"in {(int)d.TotalMinutes} min";
        if (d.TotalDays < 1) return $"in {d.TotalHours:0.#} h";
        return $"in {(int)d.TotalDays} d";
    }
}
