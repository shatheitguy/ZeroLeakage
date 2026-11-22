using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.Services;

namespace ZeroLeakage.UI.Controls;

/// <summary>Animated 3-segment pill that switches the protection mode in one click.</summary>
public partial class ModeSwitcher : UserControl
{
    public static readonly DependencyProperty ModeProperty = DependencyProperty.Register(
        nameof(Mode), typeof(ProtectionMode), typeof(ModeSwitcher),
        new FrameworkPropertyMetadata(ProtectionMode.Balanced, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault,
            (d, _) => ((ModeSwitcher)d).UpdateVisuals(animate: true)));

    private readonly SolidColorBrush _fill = new();
    private readonly SolidColorBrush _line = new();
    private readonly SolidColorBrush _accentText = new();
    private static readonly Brush SecondaryText = new SolidColorBrush(Color.FromRgb(0x9A, 0xA3, 0xB5));

    public ModeSwitcher()
    {
        InitializeComponent();
        Indicator.Background = _fill;
        Indicator.BorderBrush = _line;
        Host.SizeChanged += (_, _) => UpdateVisuals(animate: false);
        Loaded += (_, _) => UpdateVisuals(animate: false);
    }

    public ProtectionMode Mode { get => (ProtectionMode)GetValue(ModeProperty); set => SetValue(ModeProperty, value); }

    private void OnSegmentClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string tag } && Enum.TryParse<ProtectionMode>(tag, out var mode))
            Mode = mode;
    }

    private void UpdateVisuals(bool animate)
    {
        if (Host.ActualWidth <= 0) return;

        int index = (int)Mode - 1;
        double segment = Host.ActualWidth / 3;
        Indicator.Width = segment;

        var c = ThemeManager.ColorFor(Mode);
        var duration = TimeSpan.FromMilliseconds(animate ? 380 : 0);
        var ease = new CubicEase { EasingMode = EasingMode.EaseInOut };

        IndicatorShift.BeginAnimation(TranslateTransform.XProperty,
            new DoubleAnimation(index * segment, duration) { EasingFunction = ease });
        _fill.BeginAnimation(SolidColorBrush.ColorProperty, new ColorAnimation(ThemeManager.WithAlpha(c, 0x24), duration));
        _line.BeginAnimation(SolidColorBrush.ColorProperty, new ColorAnimation(ThemeManager.WithAlpha(c, 0x99), duration));
        _accentText.BeginAnimation(SolidColorBrush.ColorProperty, new ColorAnimation(c, duration));
        IndicatorGlow.BeginAnimation(DropShadowEffect.ColorProperty, new ColorAnimation(c, duration));

        var labels = new (Run Num, Run Label)[] { (Num1, Lbl1), (Num2, Lbl2), (Num3, Lbl3) };
        for (int i = 0; i < labels.Length; i++)
        {
            var brush = i == index ? _accentText : SecondaryText;
            labels[i].Num.Foreground = brush;
            labels[i].Label.Foreground = i == index ? (Brush)FindResource("Brush.TextPrimary") : SecondaryText;
        }
    }
}
