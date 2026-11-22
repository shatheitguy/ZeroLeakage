using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using ZeroLeakage.UI.Interop;
using ZeroLeakage.UI.Services;
using ZeroLeakage.UI.ViewModels;

namespace ZeroLeakage.UI;

public partial class MainWindow : Window
{
    private readonly UiSettings _settings;
    private bool _allowClose;

    public event Action? ExitRequested;

    public MainWindow(MainViewModel viewModel, UiSettings settings)
    {
        InitializeComponent();
        DataContext = viewModel;
        _settings = settings;

        SourceInitialized += (_, _) => WindowEffects.Apply(this);
        StateChanged += (_, _) => SyncMaximizedState();
        Loaded += (_, _) => StartStatusPulse();
        RootBorder.RenderTransformOrigin = new Point(0.5, 0.5);
    }

    private void StartStatusPulse()
    {
        var scale = new DoubleAnimation(0.6, 1.7, TimeSpan.FromSeconds(1.6)) { RepeatBehavior = RepeatBehavior.Forever };
        var fade = new DoubleAnimation(0.55, 0, TimeSpan.FromSeconds(1.6)) { RepeatBehavior = RepeatBehavior.Forever };
        StatusHaloScale.BeginAnimation(ScaleTransform.ScaleXProperty, scale);
        StatusHaloScale.BeginAnimation(ScaleTransform.ScaleYProperty, scale);
        StatusHalo.BeginAnimation(OpacityProperty, fade);
    }

    /// <summary>WindowChrome windows overhang the monitor by the resize border when maximized — pad it back in.</summary>
    private void SyncMaximizedState()
    {
        if (WindowState == WindowState.Maximized)
        {
            var b = SystemParameters.WindowResizeBorderThickness;
            RootBorder.Margin = new Thickness(b.Left + 4, b.Top + 4, b.Right + 4, b.Bottom + 4);
            MaxButton.Content = "";
            MaxButton.ToolTip = "Restore";
        }
        else
        {
            RootBorder.Margin = new Thickness(0);
            MaxButton.Content = "";
            MaxButton.ToolTip = "Maximize";
        }
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximize(object sender, RoutedEventArgs e)
        => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e)
    {
        if (_settings.MinimizeToTray) HideToTray();
        else ExitRequested?.Invoke();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // Alt+F4 / taskbar close: same behaviour as the X button.
        if (!_allowClose)
        {
            e.Cancel = true;
            OnClose(this, new RoutedEventArgs());
        }
        base.OnClosing(e);
    }

    public void AllowClose() => _allowClose = true;

    /// <summary>Smooth shrink + fade, then hide; protection keeps running in the tray.</summary>
    public void HideToTray()
    {
        var d = TimeSpan.FromMilliseconds(180);
        var ease = new CubicEase { EasingMode = EasingMode.EaseIn };
        var fade = new DoubleAnimation(1, 0, d) { EasingFunction = ease };
        fade.Completed += (_, _) =>
        {
            Hide();
            RootBorder.BeginAnimation(OpacityProperty, null);
            RootScale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
            RootScale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
        };
        RootScale.BeginAnimation(ScaleTransform.ScaleXProperty, new DoubleAnimation(1, 0.97, d) { EasingFunction = ease });
        RootScale.BeginAnimation(ScaleTransform.ScaleYProperty, new DoubleAnimation(1, 0.97, d) { EasingFunction = ease });
        RootBorder.BeginAnimation(OpacityProperty, fade);
    }

    public void ShowFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
        var d = TimeSpan.FromMilliseconds(220);
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        RootBorder.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, d) { EasingFunction = ease });
        RootScale.BeginAnimation(ScaleTransform.ScaleXProperty, new DoubleAnimation(0.97, 1, d) { EasingFunction = ease });
        RootScale.BeginAnimation(ScaleTransform.ScaleYProperty, new DoubleAnimation(0.97, 1, d) { EasingFunction = ease });
    }
}
