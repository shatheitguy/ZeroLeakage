using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using ZeroLeakage.UI.Services;
using ZeroLeakage.UI.ViewModels;

namespace ZeroLeakage.UI;

public partial class App : Application
{
    private Mutex? _singleInstance;
    private IProtectionEngine? _engine;

    /// <summary>Real filter-list subscriptions (shared by the engine and the DNS page).</summary>
    public static ZeroLeakage.UI.Services.Dns.FilterListService Filters { get; private set; } = null!;
    /// <summary>Offline IP-to-country database.</summary>
    public static ZeroLeakage.UI.Services.Dns.GeoIpService GeoIp { get; private set; } = null!;
    private TrayIconService? _tray;
    private ConnectToastService? _toasts;
    private MainWindow? _window;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // The self-test gets its own lock so it can run next to an installed copy.
        bool selfTest = e.Args.Contains("--selftest");
        bool startInTray = e.Args.Any(a => a.Equals("--tray", StringComparison.OrdinalIgnoreCase));
        var lockName = selfTest ? @"Local\ZeroLeakage.UI.SelfTest" : @"Local\ZeroLeakage.UI.SingleInstance";
        _singleInstance = new Mutex(true, lockName, out bool isFirst);
        if (!isFirst)
        {
            // Already running (usually hidden in the tray): bring that window forward instead of starting twice.
            if (!startInTray && !selfTest && EventWaitHandle.TryOpenExisting(ShowSignalName, out var signal))
            {
                signal.Set();
                signal.Dispose();
            }
            _singleInstance.Dispose();
            _singleInstance = null;
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandledException;
        // Errors inside async commands are shown as a snackbar; also log + count them so --selftest catches them.
        ZeroLeakage.UI.Mvvm.AsyncRelayCommand.UnhandledError += ex => LogError(ex);
        // Sign-out, shutdown, or an installer asking us to close (Restart Manager): exit for real, don't hide.
        SessionEnding += (_, _) => ExitApplication();

        var settings = UiSettingsStore.Load();
        ThemeManager.Initialize(Resources, settings.Mode);
        if (!selfTest) AutoStart.EnsureOnLaunch(settings);
        SplashWindow? splash = null;
        if (!startInTray)
        {
            splash = new SplashWindow();
            splash.Show();
        }

        // Swap SimulatedProtectionEngine for the ZeroLeakage Core service client when it is available.
        Filters = new ZeroLeakage.UI.Services.Dns.FilterListService();
        GeoIp = new ZeroLeakage.UI.Services.Dns.GeoIpService();
        _engine = new SimulatedProtectionEngine(Filters);
        _engine.SetModeAsync(settings.Mode);

        var shell = new MainViewModel(_engine, settings);
        _window = new MainWindow(shell, settings);
        _tray = new TrayIconService(_window, shell, ExitApplication);
        _toasts = new ConnectToastService(_engine, Dispatcher);
        _window.ExitRequested += ExitApplication;
        shell.ExitRequested += ExitApplication;   // profile menu Exit, or the updater handing over to msiexec
        _window.HiddenToTray += () =>
        {
            if (settings.TrayHintShown || selfTest) return;
            settings.TrayHintShown = true;
            UiSettingsStore.Save(settings);
            _tray?.ShowStillRunningHint();
        };
        if (!selfTest) ListenForShowSignal();

        _engine.Start();
        _ = Filters.StartAsync();
        DefenderService.StartBackgroundRefresh();
        if (!selfTest) shell.Updates.StartAutoCheck();

        if (!settings.WizardCompleted) shell.Wizard.Open();

        if (splash is not null)
        {
            // Let the splash animation play through once, then hand over to the main window.
            var handover = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1700) };
            handover.Tick += (_, _) =>
            {
                handover.Stop();
                _window.Show();
                _window.Activate();
                splash.FadeOutAndClose();
            };
            handover.Start();
        }

        // Dev aid: `ZeroLeakage.exe --selftest` walks every page, the wizard and all three modes,
        // then exits with code 0 (clean) or 1 (errors written to ui-errors.log).
        if (e.Args.Contains("--selftest")) RunSelfTest(shell);
    }

    private int _errorCount;

    private async void RunSelfTest(MainViewModel shell)
    {
        var settings = UiSettingsStore.Load();
        var wizardWasDone = settings.WizardCompleted;
        System.Threading.Tasks.Task Wait(int ms) => System.Threading.Tasks.Task.Delay(ms);

        shell.Wizard.Open();
        await Wait(8000);                                   // audit runs
        for (int i = 0; i < 4; i++) { shell.Wizard.NextCommand.Execute(null); await Wait(4500); }

        foreach (var mode in new[] { Models.ProtectionMode.StrictGuard, Models.ProtectionMode.TotalLockdown, Models.ProtectionMode.Balanced })
        {
            shell.Mode = mode;
            foreach (var nav in shell.NavItems) { shell.SelectedNav = nav; await Wait(900); }
        }
        shell.Mode = Models.ProtectionMode.StrictGuard;     // let an Ask-to-Connect toast appear
        shell.ToggleUpdateWindowCommand.Execute(null);
        shell.Dns.WipeLogsCommand.Execute(null);
        shell.DeepScan.RefreshCommand.Execute(null);   // real Defender status + history (no scan in the self-test)
        await Wait(6000);
        File.AppendAllText(Path.Combine(UiSettingsStore.Directory, "ui-selftest.log"),
            $"[{DateTime.Now:O}] deepscan available={shell.DeepScan.DefenderAvailable} realtime={shell.DeepScan.RealtimeText} " +
            $"sigs='{shell.DeepScan.SignatureText}' lastScan='{shell.DeepScan.LastScanText}' detections={shell.DeepScan.Detections.Count} " +
            $"status='{shell.DeepScan.StatusText}'{Environment.NewLine}");
        if (Environment.GetEnvironmentVariable("ZL_SELFTEST_CLAM") == "1")
        {
            // Opt-in: real ClamAV install/update, a pipeline test with a harmless custom signature, and a real scan.
            string L(string s) => $"[{DateTime.Now:O}] clam {s}{Environment.NewLine}";
            var logPath = Path.Combine(UiSettingsStore.Directory, "ui-selftest.log");
            try
            {
                var stage = new Progress<string>(s => File.AppendAllText(logPath, L("stage: " + s)));
                var msg = ClamAvService.IsInstalled
                    ? await ClamAvService.UpdateAllAsync(stage, System.Threading.CancellationToken.None)
                    : await ClamAvService.InstallAsync(stage, System.Threading.CancellationToken.None);
                File.AppendAllText(logPath, L($"setup='{msg}' version='{await ClamAvService.VersionAsync()}' tag='{ClamAvService.InstalledTag}'"));

                // Pipeline test: our own signature for a harmless file (no real malware, no Defender alert).
                var testDir = Path.Combine(Path.GetTempPath(), "zl-clam-selftest");
                var sigDir = Path.Combine(testDir, "sigs");
                Directory.CreateDirectory(sigDir);
                var sample = Path.Combine(testDir, "sample", "zl-clam-test.bin");
                Directory.CreateDirectory(Path.GetDirectoryName(sample)!);
                var bytes = System.Text.Encoding.ASCII.GetBytes("ZeroLeakage ClamAV pipeline self-test - harmless file");
                File.WriteAllBytes(sample, bytes);
                File.WriteAllText(Path.Combine(testDir, "sample", "clean.txt"), "just text");
                var md5 = Convert.ToHexString(System.Security.Cryptography.MD5.HashData(bytes)).ToLowerInvariant();
                File.WriteAllText(Path.Combine(sigDir, "zltest.hdb"), $"{md5}:{bytes.Length}:ZeroLeakage.SelfTest.Harmless\n");
                var (hits, files, err) = await ClamAvService.ScanAsync(new[] { Path.GetDirectoryName(sample)! }, new Progress<ClamProgress>(_ => { }),
                    System.Threading.CancellationToken.None, sigDir);
                File.AppendAllText(logPath, L($"pipeline files={files} hits={string.Join(",", hits.Select(h => h.Signature))} err='{err}'"));
                if (hits.Count != 1) _errorCount++;
                foreach (var h in hits)
                {
                    var item = await QuarantineVault.QuarantineAsync(h.Path, h.Signature);
                    bool goneAfterQuarantine = !File.Exists(h.Path);
                    var restored = await QuarantineVault.RestoreAsync(item);
                    bool sameBytes = File.Exists(restored) && File.ReadAllBytes(restored).SequenceEqual(bytes);
                    File.AppendAllText(logPath, L($"vault quarantined={item.Quarantined} removed={goneAfterQuarantine} restoredSame={sameBytes}"));
                    if (!item.Quarantined || !goneAfterQuarantine || !sameBytes) _errorCount++;
                }

                // Real scan with the full ClamAV database (clean folder: expect 0 hits).
                if (ClamAvService.HasDatabase)
                {
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    var (realHits, realFiles, realErr) = await ClamAvService.ScanAsync(new[] { Path.Combine(testDir, "sample") },
                        new Progress<ClamProgress>(_ => { }), System.Threading.CancellationToken.None);
                    File.AppendAllText(logPath, L($"real-db files={realFiles} hits={realHits.Count} err='{realErr}' took={sw.Elapsed.TotalSeconds:0}s"));
                    if (realErr is not null) _errorCount++;
                }
                try { Directory.Delete(testDir, true); } catch { }
            }
            catch (Exception ex)
            {
                File.AppendAllText(logPath, L("FAILED " + ex));
                _errorCount++;
            }
        }
        if (Environment.GetEnvironmentVariable("ZL_SELFTEST_SCAN") == "1")
        {
            // Opt-in: a real Microsoft Defender quick scan through the DeepScan page (takes a few minutes).
            shell.DeepScan.QuickScanCommand.Execute(null);
            await Wait(2000);
            var scanDeadline = DateTime.Now.AddMinutes(15);
            while (shell.DeepScan.IsScanning && DateTime.Now < scanDeadline) await Wait(2000);
            File.AppendAllText(Path.Combine(UiSettingsStore.Directory, "ui-selftest.log"),
                $"[{DateTime.Now:O}] deepscan-scan finished={!shell.DeepScan.IsScanning} found={shell.DeepScan.ThreatsFound} " +
                $"status='{shell.DeepScan.StatusText}' lastScan='{shell.DeepScan.LastScanText}'{Environment.NewLine}");
        }
        await Wait(12000);
        shell.Mode = Models.ProtectionMode.Balanced;

        // DNS page: every tab, a live DNSSEC check, and the packet inspector on a real domain.
        shell.SelectedNav = shell.NavItems.First(n => n.Page == shell.Dns);
        for (int t = 0; t < 4; t++) { shell.Dns.Tab = t; await Wait(700); }
        shell.Dns.Tab = 1;
        shell.Dns.TestDnssecCommand.Execute(null);
        var probeEvent = new Models.FeedEvent(DateTime.Now, Models.FeedVerdict.Allowed, "brave.exe", null, "cloudflare.com", 443, "HTTPS");
        var inspectorVm = new ViewModels.PacketInspectorViewModel(probeEvent, _engine!);
        var inspector = new Views.PacketInspectorWindow(inspectorVm) { Owner = _window };
        if (Environment.GetEnvironmentVariable("ZL_SELFTEST_GEOIP") == "1" && !GeoIp.IsInstalled) await GeoIp.DownloadAsync();
        inspector.Show();
        await Wait(6000);
        File.AppendAllText(Path.Combine(UiSettingsStore.Directory, "ui-selftest.log"),
            $"[{DateTime.Now:O}] rules={Filters.TotalRules} lists={Filters.Lists.Count(l => l.IsEnabled)} " +
            $"dnssec=\"{shell.Dns.DnssecTestResult}\" inspector=\"{inspectorVm.Status}\" rcode={inspectorVm.RcodeText} " +
            $"dnssecInspector=\"{inspectorVm.DnssecText}\" answers={string.Join(" | ", inspectorVm.Answers.Select(a => $"{a.Type} {a.Data} {a.Location}"))}{Environment.NewLine}");
        inspector.Close();
        shell.Dns.Tab = 0;

        // Profile menu, About and the GitHub update check (network; never downloads or installs in the self-test).
        var log = Path.Combine(UiSettingsStore.Directory, "ui-selftest.log");
        shell.IsProfileMenuOpen = true;
        await Wait(900);
        bool menuShown = _window!.IsProfileMenuShown;
        shell.OpenAboutCommand.Execute(null);
        await Wait(700);
        bool menuClosed = !shell.IsProfileMenuOpen, aboutOpen = shell.About.IsOpen;
        var update = await shell.Updates.CheckAsync(userInitiated: true);
        await Wait(800);
        _ = shell.About.DetailsText;
        shell.About.CloseCommand.Execute(null);
        await Wait(500);
        File.AppendAllText(log,
            $"[{DateTime.Now:O}] profile menuShown={menuShown} menuClosedOnSelect={menuClosed} aboutOpened={aboutOpen} aboutClosed={!shell.About.IsOpen} " +
            $"version={UpdateService.CurrentVersionText} details=\"{string.Join(" | ", shell.About.Details.Select(d => $"{d.Label}={d.Value}"))}\"{Environment.NewLine}");
        File.AppendAllText(log,
            $"[{DateTime.Now:O}] update state={update.State} latest={update.Tag ?? "-"} asset={update.AssetName ?? "-"} size={update.AssetSize} " +
            $"status=\"{shell.Updates.StatusText}\" badge={shell.HasUpdateBadge} error=\"{update.Error}\"{Environment.NewLine}");
        shell.SelectedNav = shell.NavItems[^1];             // Settings page with the App updates card
        await Wait(900);
        shell.SelectedNav = shell.NavItems.First(n => n.Page == shell.DeepScan);
        await Wait(900);
        File.AppendAllText(log,
            $"[{DateTime.Now:O}] definitions version='{shell.DeepScan.SignatureVersionText}' age='{shell.DeepScan.SignatureAgeText}' " +
            $"canUpdate={shell.DeepScan.UpdateDefinitionsCommand.CanExecute(null)} (not run in self-test){Environment.NewLine}");
        shell.SelectedNav = shell.NavItems[0];
        if (!menuShown || !aboutOpen || shell.About.IsOpen) Interlocked.Increment(ref _errorCount);

        settings = UiSettingsStore.Load();
        settings.WizardCompleted = wizardWasDone;
        UiSettingsStore.Save(settings);
        int code = _errorCount == 0 ? 0 : 1;
        ExitApplication();
        Environment.ExitCode = code;
    }

    private const string ShowSignalName = @"Local\ZeroLeakage.UI.Show";
    private EventWaitHandle? _showSignal;

    /// <summary>A second launch (Start menu, desktop shortcut) sets this event; we answer by showing the window.</summary>
    private void ListenForShowSignal()
    {
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowSignalName);
        var thread = new Thread(() =>
        {
            try
            {
                while (_showSignal.WaitOne())
                {
                    if (_exiting) return;
                    Dispatcher.BeginInvoke(new Action(() => _window?.ShowFromTray()));
                }
            }
            catch (ObjectDisposedException) { }
        }) { IsBackground = true, Name = "zl-show-signal" };
        thread.Start();
    }

    private bool _exiting;

    private void ExitApplication()
    {
        if (_exiting) return;
        _exiting = true;
        _showSignal?.Set();
        _showSignal?.Dispose();
        _window?.AllowClose();
        _toasts?.Dispose();
        _tray?.Dispose();
        _engine?.Dispose();
        _singleInstance?.ReleaseMutex();
        Shutdown();
    }

    private void LogError(Exception ex)
    {
        try
        {
            Directory.CreateDirectory(UiSettingsStore.Directory);
            File.AppendAllText(Path.Combine(UiSettingsStore.Directory, "ui-errors.log"),
                $"[{DateTime.Now:O}] {ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch { /* logging must never crash the shield UI */ }
        Interlocked.Increment(ref _errorCount);
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(UiSettingsStore.Directory);
            File.AppendAllText(Path.Combine(UiSettingsStore.Directory, "ui-errors.log"),
                $"[{DateTime.Now:O}] {e.Exception}{Environment.NewLine}{Environment.NewLine}");
        }
        catch { /* logging must never crash the shield UI */ }
        _errorCount++;
        e.Handled = true;
    }
}
