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
    private TrayIconService? _tray;
    private ConnectToastService? _toasts;
    private MainWindow? _window;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _singleInstance = new Mutex(true, @"Local\ZeroLeakage.UI.SingleInstance", out bool isFirst);
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
        _engine = new SimulatedProtectionEngine();
        _engine.SetModeAsync(settings.Mode);

        var shell = new MainViewModel(_engine, settings);
        _window = new MainWindow(shell, settings);
        _tray = new TrayIconService(_window, shell, ExitApplication);
        _toasts = new ConnectToastService(_engine, Dispatcher);
        _window.ExitRequested += ExitApplication;

        _engine.Start();

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
