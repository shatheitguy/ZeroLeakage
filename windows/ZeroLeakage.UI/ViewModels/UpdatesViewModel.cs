using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using ZeroLeakage.UI.Mvvm;
using ZeroLeakage.UI.Services;

namespace ZeroLeakage.UI.ViewModels;

// ═════════════════════════════ App updates (GitHub releases) ═════════════════════════════
public sealed class UpdatesViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private readonly UiSettings _settings;
    private readonly DispatcherTimer _autoTimer;
    private UpdateCheckResult? _result;
    private bool _isChecking, _isDownloading;
    private double _downloadProgress;
    private string _statusText = "Not checked yet";
    private CancellationTokenSource? _downloadCts;

    public UpdatesViewModel(MainViewModel shell, UiSettings settings)
    {
        _shell = shell;
        _settings = settings;
        CheckCommand = new AsyncRelayCommand(() => CheckAsync(userInitiated: true), () => !IsChecking && !IsDownloading);
        InstallCommand = new AsyncRelayCommand(DownloadAndInstallAsync, () => IsUpdateAvailable && !IsDownloading && _result?.AssetUrl is not null);
        CancelDownloadCommand = new RelayCommand(() => _downloadCts?.Cancel(), () => IsDownloading);
        OpenReleasePageCommand = new RelayCommand(() => UpdateService.OpenUrl(_result?.ReleasePageUrl ?? UpdateService.ReleasesUrl));

        if (settings.LastUpdateCheck is { } last) _statusText = $"Last checked {last:dd MMM yyyy · HH:mm}";
        _autoTimer = new DispatcherTimer { Interval = TimeSpan.FromHours(1) };
        _autoTimer.Tick += (_, _) => _ = AutoCheckIfDueAsync();
    }

    public ICommand CheckCommand { get; }
    public ICommand InstallCommand { get; }
    public ICommand CancelDownloadCommand { get; }
    public ICommand OpenReleasePageCommand { get; }

    public string CurrentVersionText => "v" + UpdateService.CurrentVersionText;

    public bool IsChecking
    {
        get => _isChecking;
        private set { if (SetProperty(ref _isChecking, value)) { OnPropertyChanged(nameof(IsBusy)); CommandManager.InvalidateRequerySuggested(); } }
    }

    public bool IsDownloading
    {
        get => _isDownloading;
        private set { if (SetProperty(ref _isDownloading, value)) { OnPropertyChanged(nameof(IsBusy)); CommandManager.InvalidateRequerySuggested(); } }
    }

    public bool IsBusy => IsChecking || IsDownloading;
    public double DownloadProgress { get => _downloadProgress; private set => SetProperty(ref _downloadProgress, value); }

    public UpdateState State => _result?.State ?? UpdateState.Unknown;
    public bool IsUpdateAvailable => State == UpdateState.Available;
    public bool IsUpToDate => State == UpdateState.UpToDate;
    public bool HasError => State == UpdateState.Error;
    public string StatusText { get => _statusText; private set => SetProperty(ref _statusText, value); }
    public string? LatestVersionText => _result?.LatestVersion is { } v ? "v" + UpdateService.Display(v) : null;
    public string? ReleaseNotes => IsUpdateAvailable ? _result?.NotesSummary : null;
    public string InstallText => LatestVersionText is { } v ? $"Download & install {v}" : "Download & install";

    public bool AutoCheck
    {
        get => _settings.AutoCheckUpdates;
        set
        {
            if (_settings.AutoCheckUpdates == value) return;
            _settings.AutoCheckUpdates = value;
            UiSettingsStore.Save(_settings);
            OnPropertyChanged();
            if (value) StartAutoCheck(); else _autoTimer.Stop();
        }
    }

    /// <summary>Background check: a little after start-up, then hourly ticks that only hit GitHub once per 24 h.</summary>
    public void StartAutoCheck()
    {
        if (!_settings.AutoCheckUpdates) return;
        _autoTimer.Start();
        var first = new DispatcherTimer { Interval = TimeSpan.FromSeconds(25) };
        first.Tick += (_, _) => { first.Stop(); _ = AutoCheckIfDueAsync(); };
        first.Start();
    }

    private async Task AutoCheckIfDueAsync()
    {
        if (!_settings.AutoCheckUpdates || IsBusy) return;
        if (_settings.LastUpdateCheck is { } last && DateTime.Now - last < TimeSpan.FromHours(24)) return;
        try { await CheckAsync(userInitiated: false); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
    }

    public async Task<UpdateCheckResult> CheckAsync(bool userInitiated)
    {
        IsChecking = true;
        StatusText = "Checking GitHub for a newer release…";
        try
        {
            var result = await UpdateService.CheckAsync();
            _result = result;
            if (result.State != UpdateState.Error)
            {
                _settings.LastUpdateCheck = result.CheckedAt;
                UiSettingsStore.Save(_settings);
            }
            StatusText = result.State switch
            {
                UpdateState.UpToDate when result.LatestVersion is { } l && l < UpdateService.CurrentVersion
                    => $"You're up to date · {CurrentVersionText} is newer than the latest release ({LatestVersionText})",
                UpdateState.UpToDate => $"You're up to date · {CurrentVersionText} is the latest",
                UpdateState.Available when result.AssetUrl is null => $"{LatestVersionText} is available (no Windows installer attached yet)",
                UpdateState.Available => $"Update available · {LatestVersionText}",
                _ => $"Couldn't check: {result.Error}",
            };
            foreach (var n in new[] { nameof(State), nameof(IsUpdateAvailable), nameof(IsUpToDate), nameof(HasError),
                                      nameof(LatestVersionText), nameof(ReleaseNotes), nameof(InstallText) })
                OnPropertyChanged(n);
            UpdateAvailabilityChanged?.Invoke(this, EventArgs.Empty);

            if (userInitiated) _shell.ShowSnackbar(StatusText);
            else if (result.State == UpdateState.Available)
                _shell.ShowSnackbar($"ZeroLeakage {LatestVersionText} is available · open the profile menu to update");
            return result;
        }
        finally { IsChecking = false; }
    }

    public event EventHandler? UpdateAvailabilityChanged;

    private async Task DownloadAndInstallAsync()
    {
        if (_result is not { State: UpdateState.Available } release) return;
        _downloadCts = new CancellationTokenSource();
        IsDownloading = true;
        DownloadProgress = 0;
        StatusText = $"Downloading {release.AssetName}…";
        try
        {
            var path = await UpdateService.DownloadAsync(release, new Progress<double>(p => DownloadProgress = p), _downloadCts.Token);
            StatusText = "Starting the installer · ZeroLeakage will close and reopen after the upgrade";
            UpdateService.LaunchInstaller(path);
            await Task.Delay(600);
            _shell.RequestExit();
        }
        catch (OperationCanceledException)
        {
            StatusText = "Download cancelled";
        }
        catch (Exception ex)
        {
            StatusText = $"Update failed: {ex.Message}";
            _shell.ShowSnackbar(StatusText);
        }
        finally
        {
            _downloadCts.Dispose();
            _downloadCts = null;
            IsDownloading = false;
        }
    }
}

// ═════════════════════════════ About ZeroLeakage ═════════════════════════════
public sealed record AboutDetail(string Label, string Value);

public sealed class AboutViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private bool _isOpen;

    public AboutViewModel(MainViewModel shell, UpdatesViewModel updates)
    {
        _shell = shell;
        Updates = updates;
        Details = BuildDetails();
        CloseCommand = new RelayCommand(() => IsOpen = false);
        OpenLinkCommand = new RelayCommand(p => { if (p is string url) UpdateService.OpenUrl(url); });
        CopyDetailsCommand = new RelayCommand(CopyDetails);
    }

    public UpdatesViewModel Updates { get; }
    public IReadOnlyList<AboutDetail> Details { get; }
    public ICommand CloseCommand { get; }
    public ICommand OpenLinkCommand { get; }
    public ICommand CopyDetailsCommand { get; }

    public bool IsOpen { get => _isOpen; set => SetProperty(ref _isOpen, value); }

    public string VersionText => "Version " + UpdateService.CurrentVersionText + (UpdateService.SourceRevision is { } r ? $" ({r})" : "");
    public string WebsiteUrl => UpdateService.WebsiteUrl;
    public string GitHubUrl => UpdateService.GitHubUrl;
    public string ReleasesUrl => UpdateService.ReleasesUrl;

    public string EngineFirewallText => "Simulated preview: the live feed, firewall rules and telemetry blocking are a stand-in for the ZeroLeakage Core service and change nothing on this PC yet.";
    public string EngineDefenderText => "Real: scans, detections, quarantine and definitions come from Microsoft Defender.";

    private static IReadOnlyList<AboutDetail> BuildDetails()
    {
        var exe = Environment.ProcessPath ?? Assembly.GetEntryAssembly()?.Location ?? "";
        var installDir = string.IsNullOrEmpty(exe) ? AppContext.BaseDirectory : Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory;
        return new List<AboutDetail>
        {
            new("Version", UpdateService.CurrentVersionText + (UpdateService.SourceRevision is { } r ? $" · {r}" : "")),
            new("Build date", BuildDate(exe)),
            new(".NET runtime", RuntimeInformation.FrameworkDescription + " · " + RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()),
            new("Windows", $"{RuntimeInformation.OSDescription.Replace("Microsoft Windows ", "")} · {RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant()}"),
            new("Install path", installDir.TrimEnd('\\')),
            new("Data folder", UiSettingsStore.Directory),
        };
    }

    private static string BuildDate(string exe)
    {
        var stamp = Assembly.GetEntryAssembly()?.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "BuildDate")?.Value;
        if (DateTime.TryParse(stamp, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d))
            return d.ToLocalTime().ToString("dd MMM yyyy · HH:mm");
        try { return File.GetLastWriteTime(exe).ToString("dd MMM yyyy · HH:mm"); }
        catch { return "Unknown"; }
    }

    public string DetailsText =>
        "ZeroLeakage" + Environment.NewLine +
        string.Join(Environment.NewLine, Details.Select(d => $"{d.Label}: {d.Value}")) + Environment.NewLine +
        "Firewall / telemetry engine: simulated preview" + Environment.NewLine +
        "DeepScan AV: Microsoft Defender" + (DefenderService.LastStatus is { Available: true } s ? $" (signatures {s.SignatureVersion})" : "") + Environment.NewLine +
        $"Update status: {Updates.StatusText}";

    private void CopyDetails()
    {
        try
        {
            Clipboard.SetText(DetailsText);
            _shell.ShowSnackbar("App details copied to the clipboard");
        }
        catch (Exception ex) { _shell.ShowSnackbar($"Couldn't copy: {ex.Message}"); }
    }
}
