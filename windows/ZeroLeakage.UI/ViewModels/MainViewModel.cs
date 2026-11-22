using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.Mvvm;
using ZeroLeakage.UI.Services;

namespace ZeroLeakage.UI.ViewModels;

public sealed record NavItem(string Title, string Glyph, ObservableObject Page);

public sealed record ConfirmRequest(string Title, string Message, string ConfirmText, bool IsDestructive, Func<Task> Action);

internal static class Ui
{
    public static void Post(Action action) => Application.Current?.Dispatcher.InvokeAsync(action);
}

public sealed class MainViewModel : ObservableObject
{
    private readonly IProtectionEngine _engine;
    private readonly UiSettings _settings;
    private readonly DispatcherTimer _clock;
    private readonly DispatcherTimer _snackTimer;

    private ProtectionMode _mode;
    private NavItem _selectedNav;
    private ObservableObject _currentPage;
    private DateTime? _updateWindowEnds;
    private ConfirmRequest? _confirm;
    private string? _snackbar;
    private bool _isBusy;

    public MainViewModel(IProtectionEngine engine, UiSettings settings)
    {
        _engine = engine;
        _settings = settings;
        _mode = settings.Mode;

        Dashboard = new DashboardViewModel(this, engine);
        Firewall = new FirewallViewModel(this, engine);
        Dns = new DnsTelemetryViewModel(this, engine);
        DeepScan = new DeepScanViewModel(this, engine);
        Updates = new UpdatesViewModel(this, settings);
        About = new AboutViewModel(this, Updates);
        Settings = new SettingsViewModel(this, engine, settings);
        Wizard = new AuditWizardViewModel(this, engine, settings);

        NavItems = new List<NavItem>
        {
            new("Dashboard", "", Dashboard),
            new("Firewall Rules", "", Firewall),
            new("DNS & Telemetry", "", Dns),
            new("DeepScan AV", "", DeepScan),
            new("Snapshots & Settings", "", Settings),
        };
        _selectedNav = NavItems[0];
        _currentPage = Dashboard;

        SetModeCommand = new RelayCommand(p =>
        {
            if (p is ProtectionMode m) Mode = m;
            else if (p is string s && Enum.TryParse<ProtectionMode>(s, out var parsed)) Mode = parsed;
        });
        ToggleUpdateWindowCommand = new AsyncRelayCommand(ToggleUpdateWindowAsync);
        RestoreDefaultsCommand = new RelayCommand(() => RequestConfirm(
            "Restore defaults?",
            "Removes every ZeroLeakage_Core firewall rule, custom DNS block and app kill-switch, and returns to Mode 1: Balanced Shield. Snapshots and Microsoft Defender quarantine are kept.",
            "Restore defaults", true, RestoreDefaultsAsync));
        ConfirmAcceptCommand = new AsyncRelayCommand(AcceptConfirmAsync);
        ConfirmCancelCommand = new RelayCommand(() => Confirm = null);
        DismissSnackbarCommand = new RelayCommand(() => Snackbar = null);

        // Profile menu (bottom of the left rail)
        OpenSettingsCommand = new RelayCommand(() => { IsProfileMenuOpen = false; SelectedNav = NavItems[^1]; });
        OpenAboutCommand = new RelayCommand(() => { IsProfileMenuOpen = false; About.IsOpen = true; });
        CheckForUpdatesCommand = new RelayCommand(() =>
        {
            IsProfileMenuOpen = false;
            About.IsOpen = true;   // the About card shows the result and the install button
            if (Updates.CheckCommand.CanExecute(null)) Updates.CheckCommand.Execute(null);
        });
        UpdateDefinitionsCommand = new RelayCommand(() =>
        {
            IsProfileMenuOpen = false;
            SelectedNav = NavItems.First(n => n.Page == DeepScan);
            if (DeepScan.UpdateDefinitionsCommand.CanExecute(null)) DeepScan.UpdateDefinitionsCommand.Execute(null);
        });
        ExitCommand = new RelayCommand(() => { IsProfileMenuOpen = false; RequestExit(); });
        Updates.UpdateAvailabilityChanged += (_, _) => OnPropertyChanged(nameof(HasUpdateBadge));

        _clock = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clock.Tick += (_, _) => TickUpdateWindow();
        _snackTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3.5) };
        _snackTimer.Tick += (_, _) => { _snackTimer.Stop(); Snackbar = null; };

        AsyncRelayCommand.UnhandledError += ex => Ui.Post(() => ShowSnackbar($"Error: {ex.Message}"));
    }

    // ───────────── child pages ─────────────
    public DashboardViewModel Dashboard { get; }
    public FirewallViewModel Firewall { get; }
    public DnsTelemetryViewModel Dns { get; }
    public DeepScanViewModel DeepScan { get; }
    public SettingsViewModel Settings { get; }
    public AuditWizardViewModel Wizard { get; }
    public UpdatesViewModel Updates { get; }
    public AboutViewModel About { get; }
    public IReadOnlyList<NavItem> NavItems { get; }

    // ───────────── profile menu ─────────────
    private bool _isProfileMenuOpen;
    public bool IsProfileMenuOpen { get => _isProfileMenuOpen; set => SetProperty(ref _isProfileMenuOpen, value); }
    public bool HasUpdateBadge => Updates.IsUpdateAvailable;
    public string VersionShort => "v" + UpdateService.CurrentVersionText;
    public ICommand OpenSettingsCommand { get; }
    public ICommand OpenAboutCommand { get; }
    public ICommand CheckForUpdatesCommand { get; }
    public ICommand UpdateDefinitionsCommand { get; }
    public ICommand ExitCommand { get; }

    /// <summary>Raised when the user asks to quit (profile menu Exit, or the updater handing over to msiexec).</summary>
    public event Action? ExitRequested;
    public void RequestExit() => ExitRequested?.Invoke();

    public NavItem SelectedNav
    {
        get => _selectedNav;
        set
        {
            if (value is null || !SetProperty(ref _selectedNav, value)) return;
            if (value.Page == Firewall) Firewall.Refresh();
            if (value.Page == DeepScan) DeepScan.Refresh();
            CurrentPage = value.Page;
        }
    }

    public ObservableObject CurrentPage { get => _currentPage; private set => SetProperty(ref _currentPage, value); }

    // ───────────── protection mode ─────────────
    public ProtectionMode Mode
    {
        get => _mode;
        set
        {
            if (!SetProperty(ref _mode, value)) return;
            OnPropertyChanged(nameof(ModeLabel));
            OnPropertyChanged(nameof(ModeTitle));
            OnPropertyChanged(nameof(ModeDescription));
            OnPropertyChanged(nameof(ModeColor));
            ThemeManager.Apply(value);
            _settings.Mode = value;
            UiSettingsStore.Save(_settings);
            _ = _engine.SetModeAsync(value);
            ShowSnackbar(value switch
            {
                ProtectionMode.Balanced => "Mode 1 · Balanced Shield engaged",
                ProtectionMode.StrictGuard => "Mode 2 · Strict Guard — unknown apps must ask to connect",
                _ => "Mode 3 · Total Zero-Leak — all non-essential traffic dropped",
            });
            ModeChanged?.Invoke(this, value);
        }
    }

    public event EventHandler<ProtectionMode>? ModeChanged;

    public string ModeLabel => Mode switch
    {
        ProtectionMode.Balanced => "MODE 1: BALANCED",
        ProtectionMode.StrictGuard => "MODE 2: STRICT GUARD",
        _ => "MODE 3: TOTAL ZERO-LEAK",
    };

    public string ModeTitle => Mode switch
    {
        ProtectionMode.Balanced => "Balanced Shield",
        ProtectionMode.StrictGuard => "Strict Guard",
        _ => "Total Zero-Leak",
    };

    public string ModeDescription => Mode switch
    {
        ProtectionMode.Balanced => "OS telemetry, ad trackers and analytics SDKs are silently dropped. Your apps keep working exactly as before.",
        ProtectionMode.StrictGuard => "Everything in Balanced, plus default-deny outbound: any unapproved .exe must ask before it touches the network.",
        _ => "Hard lockdown. Only encrypted DNS and explicitly pinned apps may leave this machine — everything else is dropped.",
    };

    public Color ModeColor => ThemeManager.ColorFor(Mode);

    public ICommand SetModeCommand { get; }

    // ───────────── update window ─────────────
    public bool IsUpdateWindowOpen => _updateWindowEnds is not null;

    public string UpdateWindowText
    {
        get
        {
            if (_updateWindowEnds is not { } end) return $"Update Window ({_settings.UpdateWindowMinutes}m)";
            var left = end - DateTime.Now;
            if (left < TimeSpan.Zero) left = TimeSpan.Zero;
            return $"Update Window · {(int)left.TotalMinutes:00}:{left.Seconds:00}";
        }
    }

    public ICommand ToggleUpdateWindowCommand { get; }

    private async Task ToggleUpdateWindowAsync()
    {
        if (_updateWindowEnds is not null)
        {
            await _engine.CloseUpdateWindowAsync();
            _updateWindowEnds = null;
            _clock.Stop();
            ShowSnackbar("Update window closed — Windows Update traffic blocked again");
        }
        else
        {
            _updateWindowEnds = await _engine.OpenUpdateWindowAsync(TimeSpan.FromMinutes(_settings.UpdateWindowMinutes));
            _clock.Start();
            ShowSnackbar($"Windows Update allowed for {_settings.UpdateWindowMinutes} minutes");
        }
        OnPropertyChanged(nameof(IsUpdateWindowOpen));
        OnPropertyChanged(nameof(UpdateWindowText));
    }

    private void TickUpdateWindow()
    {
        if (_updateWindowEnds is { } end && DateTime.Now >= end)
        {
            _updateWindowEnds = null;
            _clock.Stop();
            OnPropertyChanged(nameof(IsUpdateWindowOpen));
            ShowSnackbar("Update window expired — back to zero-leak");
        }
        OnPropertyChanged(nameof(UpdateWindowText));
    }

    internal void RefreshUpdateWindowLabel() => OnPropertyChanged(nameof(UpdateWindowText));

    // ───────────── restore defaults ─────────────
    public ICommand RestoreDefaultsCommand { get; }

    public bool IsBusy { get => _isBusy; private set => SetProperty(ref _isBusy, value); }

    private async Task RestoreDefaultsAsync()
    {
        IsBusy = true;
        try
        {
            await _engine.RestoreDefaultsAsync();
            if (_updateWindowEnds is not null) { _updateWindowEnds = null; _clock.Stop(); OnPropertyChanged(nameof(IsUpdateWindowOpen)); }
            OnPropertyChanged(nameof(UpdateWindowText));
            Mode = ProtectionMode.Balanced;
            Firewall.Refresh();
            ShowSnackbar("Defaults restored · Mode 1 Balanced Shield");
        }
        finally { IsBusy = false; }
    }

    // ───────────── confirm overlay ─────────────
    public ConfirmRequest? Confirm { get => _confirm; private set => SetProperty(ref _confirm, value); }
    public ICommand ConfirmAcceptCommand { get; }
    public ICommand ConfirmCancelCommand { get; }

    public void RequestConfirm(string title, string message, string confirmText, bool destructive, Func<Task> action)
        => Confirm = new ConfirmRequest(title, message, confirmText, destructive, action);

    private async Task AcceptConfirmAsync()
    {
        var req = Confirm;
        Confirm = null;
        if (req is not null) await req.Action();
    }

    // ───────────── snackbar ─────────────
    public string? Snackbar { get => _snackbar; private set => SetProperty(ref _snackbar, value); }
    public ICommand DismissSnackbarCommand { get; }

    public void ShowSnackbar(string text)
    {
        Snackbar = text;
        _snackTimer.Stop();
        _snackTimer.Start();
    }
}
