using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace ZeroLeakage.UI.Controls;

/// <summary>
/// DeepScan's scanner visual: a radar with a rotating sweep, pulse rings and "blips" while scanning,
/// and a calm breathing glow when idle. Accent turns crimson when threats are present.
/// </summary>
public partial class ScanRadar : UserControl
{
    public static readonly DependencyProperty IsScanningProperty = DependencyProperty.Register(
        nameof(IsScanning), typeof(bool), typeof(ScanRadar), new PropertyMetadata(false, (d, _) => ((ScanRadar)d).UpdateState()));
    public static readonly DependencyProperty AlertProperty = DependencyProperty.Register(
        nameof(Alert), typeof(bool), typeof(ScanRadar), new PropertyMetadata(false, (d, _) => ((ScanRadar)d).ApplyColors()));
    public static readonly DependencyProperty CenterTextProperty = DependencyProperty.Register(
        nameof(CenterText), typeof(string), typeof(ScanRadar), new PropertyMetadata("✓"));
    public static readonly DependencyProperty CaptionTextProperty = DependencyProperty.Register(
        nameof(CaptionText), typeof(string), typeof(ScanRadar), new PropertyMetadata("PROTECTED"));
    /// <summary>Bumped by the view-model as files are scanned; each change can spawn a blip.</summary>
    public static readonly DependencyProperty ActivityProperty = DependencyProperty.Register(
        nameof(Activity), typeof(long), typeof(ScanRadar), new PropertyMetadata(0L, (d, _) => ((ScanRadar)d).OnActivity()));

    public bool IsScanning { get => (bool)GetValue(IsScanningProperty); set => SetValue(IsScanningProperty, value); }
    public bool Alert { get => (bool)GetValue(AlertProperty); set => SetValue(AlertProperty, value); }
    public string CenterText { get => (string)GetValue(CenterTextProperty); set => SetValue(CenterTextProperty, value); }
    public string CaptionText { get => (string)GetValue(CaptionTextProperty); set => SetValue(CaptionTextProperty, value); }
    public long Activity { get => (long)GetValue(ActivityProperty); set => SetValue(ActivityProperty, value); }

    private static readonly Color Mint = Color.FromRgb(0x00, 0xF5, 0xA0);
    private static readonly Color Crimson = Color.FromRgb(0xFF, 0x2E, 0x54);
    private readonly Random _rng = new();
    private readonly DispatcherTimer _blipTimer = new() { Interval = TimeSpan.FromMilliseconds(260) };
    private DateTime _lastBlip;

    public ScanRadar()
    {
        InitializeComponent();
        _blipTimer.Tick += (_, _) => SpawnBlip();
        Loaded += (_, _) => { ApplyColors(); UpdateState(); };
        Unloaded += (_, _) => _blipTimer.Stop();
    }

    private Color Accent => Alert ? Crimson : Mint;

    private void ApplyColors()
    {
        var c = Accent;
        var brush = new SolidColorBrush(c);
        Outer.Stroke = brush;
        Edge.Stroke = brush;
        Pulse1.Stroke = brush;
        Pulse2.Stroke = brush;
        WedgeA.Color = Color.FromArgb(0, c.R, c.G, c.B);
        WedgeB.Color = Color.FromArgb(0x60, c.R, c.G, c.B);
        GlowInner.Color = Color.FromArgb(0x38, c.R, c.G, c.B);
    }

    private void UpdateState()
    {
        if (!IsLoaded) return;
        var ease = new SineEase { EasingMode = EasingMode.EaseInOut };
        if (IsScanning)
        {
            Sweep.BeginAnimation(OpacityProperty, new DoubleAnimation(1, TimeSpan.FromMilliseconds(250)));
            SweepRotate.BeginAnimation(RotateTransform.AngleProperty,
                new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.8)) { RepeatBehavior = RepeatBehavior.Forever });
            StartPulse(Pulse1, Pulse1Scale, TimeSpan.Zero);
            StartPulse(Pulse2, Pulse2Scale, TimeSpan.FromSeconds(1.1));
            Outer.StrokeDashArray = new DoubleCollection { 6, 4 };
            Outer.BeginAnimation(Shape.StrokeDashOffsetProperty,
                new DoubleAnimation(0, -40, TimeSpan.FromSeconds(1.6)) { RepeatBehavior = RepeatBehavior.Forever });
            Glow.BeginAnimation(OpacityProperty, new DoubleAnimation(0.9, TimeSpan.FromMilliseconds(300)));
            _blipTimer.Start();
        }
        else
        {
            Sweep.BeginAnimation(OpacityProperty, new DoubleAnimation(0, TimeSpan.FromMilliseconds(400)));
            SweepRotate.BeginAnimation(RotateTransform.AngleProperty, null);
            foreach (var p in new[] { Pulse1, Pulse2 }) p.BeginAnimation(OpacityProperty, null);
            Pulse1.Opacity = Pulse2.Opacity = 0;
            Outer.BeginAnimation(Shape.StrokeDashOffsetProperty, null);
            Outer.StrokeDashArray = null;
            Glow.BeginAnimation(OpacityProperty,
                new DoubleAnimation(0.35, 0.75, TimeSpan.FromSeconds(2.4)) { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever, EasingFunction = ease });
            _blipTimer.Stop();
        }
    }

    private static void StartPulse(Ellipse e, ScaleTransform s, TimeSpan delay)
    {
        var d = TimeSpan.FromSeconds(2.2);
        var scale = new DoubleAnimation(0.35, 1.0, d) { BeginTime = delay, RepeatBehavior = RepeatBehavior.Forever, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
        s.BeginAnimation(ScaleTransform.ScaleXProperty, scale);
        s.BeginAnimation(ScaleTransform.ScaleYProperty, scale);
        e.BeginAnimation(OpacityProperty, new DoubleAnimation(0.7, 0, d) { BeginTime = delay, RepeatBehavior = RepeatBehavior.Forever });
    }

    private void OnActivity()
    {
        if (IsScanning && (DateTime.UtcNow - _lastBlip).TotalMilliseconds > 90) SpawnBlip();
    }

    /// <summary>A dot that flashes in somewhere inside the scope and fades out.</summary>
    private void SpawnBlip()
    {
        if (!IsScanning || Blips.Children.Count > 14) return;
        _lastBlip = DateTime.UtcNow;
        double angle = _rng.NextDouble() * Math.PI * 2, radius = 26 + _rng.NextDouble() * 64;
        double size = 3 + _rng.NextDouble() * 3;
        var c = Accent;
        var dot = new Ellipse
        {
            Width = size, Height = size,
            Fill = new SolidColorBrush(c),
            Effect = null,
        };
        Canvas.SetLeft(dot, 110 + Math.Cos(angle) * radius - size / 2);
        Canvas.SetTop(dot, 110 + Math.Sin(angle) * radius - size / 2);
        Blips.Children.Add(dot);
        var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(900)) { BeginTime = TimeSpan.FromMilliseconds(120) };
        fade.Completed += (_, _) => Blips.Children.Remove(dot);
        dot.BeginAnimation(OpacityProperty, fade);
    }
}
