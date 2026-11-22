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
        var lockName = e.Args.Contains("--selftest") ? @"Local\ZeroLeakage.UI.SelfTest" : @"Local\ZeroLeakage.UI.SingleInstance";
        _singleInstance = new Mutex(true, lockName, out bool isFirst);
        if (!isFirst)
        {
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandledException;

        var settings = UiSettingsStore.Load();
        ThemeManager.Initialize(Resources, settings.Mode);

        bool startInTray = e.Args.Any(a => a.Equals("--tray", StringComparison.OrdinalIgnoreCase));
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

        _engine.Start();
        _ = Filters.StartAsync();

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
        shell.DeepScan.QuickScanCommand.Execute(null);
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

        settings = UiSettingsStore.Load();
        settings.WizardCompleted = wizardWasDone;
        UiSettingsStore.Save(settings);
        int code = _errorCount == 0 ? 0 : 1;
        ExitApplication();
        Environment.ExitCode = code;
    }

    private void ExitApplication()
    {
        _window?.AllowClose();
        _toasts?.Dispose();
        _tray?.Dispose();
        _engine?.Dispose();
        _singleInstance?.ReleaseMutex();
        Shutdown();
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
