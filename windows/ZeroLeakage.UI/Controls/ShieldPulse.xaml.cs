using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace ZeroLeakage.UI.Controls;

/// <summary>Radial "sonar" pulse that shows the shield is live, tinted by the active mode.</summary>
public partial class ShieldPulse : UserControl
{
    public static readonly DependencyProperty AccentColorProperty = DependencyProperty.Register(
        nameof(AccentColor), typeof(Color), typeof(ShieldPulse),
        new PropertyMetadata(Color.FromRgb(0x00, 0xF5, 0xA0), (d, e) => ((ShieldPulse)d).Retint((Color)e.NewValue, true)));

    private readonly SolidColorBrush _stroke = new(Color.FromRgb(0x00, 0xF5, 0xA0));
    private readonly GradientStop _haloInner = new(Color.FromArgb(0x55, 0x00, 0xF5, 0xA0), 0);
    private readonly GradientStop _haloOuter = new(Color.FromArgb(0x00, 0x00, 0xF5, 0xA0), 1);

    public ShieldPulse()
    {
        InitializeComponent();
        foreach (var r in new[] { Ring1, Ring2, Ring3 }) r.Stroke = _stroke;
        Core.Stroke = _stroke;
        Glyph.Foreground = _stroke;
        Halo.Fill = new RadialGradientBrush(new GradientStopCollection { _haloInner, _haloOuter });
        Loaded += (_, _) => StartPulse();
        Unloaded += (_, _) => StopPulse();
        Retint(AccentColor, false);
    }

    public Color AccentColor { get => (Color)GetValue(AccentColorProperty); set => SetValue(AccentColorProperty, value); }

    private void StartPulse()
    {
        var rings = new (Ellipse Ring, ScaleTransform Scale)[] { (Ring1, Scale1), (Ring2, Scale2), (Ring3, Scale3) };
        var period = TimeSpan.FromSeconds(2.7);
        for (int i = 0; i < rings.Length; i++)
        {
            var begin = TimeSpan.FromSeconds(i * 0.9);
            var ease = new QuadraticEase { EasingMode = EasingMode.EaseOut };
            var scale = new DoubleAnimation(0.58, 1.0, period) { BeginTime = begin, RepeatBehavior = RepeatBehavior.Forever, EasingFunction = ease };
            var fade = new DoubleAnimation(0.75, 0.0, period) { BeginTime = begin, RepeatBehavior = RepeatBehavior.Forever };
            rings[i].Scale.BeginAnimation(ScaleTransform.ScaleXProperty, scale);
            rings[i].Scale.BeginAnimation(ScaleTransform.ScaleYProperty, scale);
            rings[i].Ring.BeginAnimation(OpacityProperty, fade);
        }
        Halo.BeginAnimation(OpacityProperty, new DoubleAnimation(0.55, 1.0, TimeSpan.FromSeconds(1.6))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
        });
    }

    private void StopPulse()
    {
        foreach (var s in new[] { Scale1, Scale2, Scale3 })
        {
            s.BeginAnimation(ScaleTransform.ScaleXProperty, null);
            s.BeginAnimation(ScaleTransform.ScaleYProperty, null);
        }
        foreach (var r in new[] { Ring1, Ring2, Ring3 }) r.BeginAnimation(OpacityProperty, null);
        Halo.BeginAnimation(OpacityProperty, null);
    }

    private void Retint(Color c, bool animate)
    {
        var d = TimeSpan.FromMilliseconds(animate ? 450 : 0);
        _stroke.BeginAnimation(SolidColorBrush.ColorProperty, new ColorAnimation(c, d));
        _haloInner.BeginAnimation(GradientStop.ColorProperty, new ColorAnimation(Color.FromArgb(0x55, c.R, c.G, c.B), d));
        _haloOuter.BeginAnimation(GradientStop.ColorProperty, new ColorAnimation(Color.FromArgb(0x00, c.R, c.G, c.B), d));
    }
}
