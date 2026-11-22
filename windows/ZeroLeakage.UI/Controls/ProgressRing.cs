using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace ZeroLeakage.UI.Controls;

/// <summary>Lightweight circular progress ring (determinate 0–100, or indeterminate spinner).</summary>
public sealed class ProgressRing : FrameworkElement
{
    public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
        nameof(Value), typeof(double), typeof(ProgressRing),
        new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ThicknessProperty = DependencyProperty.Register(
        nameof(Thickness), typeof(double), typeof(ProgressRing),
        new FrameworkPropertyMetadata(8d, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(Brush), typeof(ProgressRing),
        new FrameworkPropertyMetadata(Brushes.White, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TrackProperty = DependencyProperty.Register(
        nameof(Track), typeof(Brush), typeof(ProgressRing),
        new FrameworkPropertyMetadata(MakeTrack(), FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty IsIndeterminateProperty = DependencyProperty.Register(
        nameof(IsIndeterminate), typeof(bool), typeof(ProgressRing),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender, (d, _) => ((ProgressRing)d).UpdateSpin()));

    private static readonly DependencyProperty SpinProperty = DependencyProperty.Register(
        "Spin", typeof(double), typeof(ProgressRing),
        new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

    public double Value { get => (double)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public double Thickness { get => (double)GetValue(ThicknessProperty); set => SetValue(ThicknessProperty, value); }
    public Brush Stroke { get => (Brush)GetValue(StrokeProperty); set => SetValue(StrokeProperty, value); }
    public Brush Track { get => (Brush)GetValue(TrackProperty); set => SetValue(TrackProperty, value); }
    public bool IsIndeterminate { get => (bool)GetValue(IsIndeterminateProperty); set => SetValue(IsIndeterminateProperty, value); }

    private static Brush MakeTrack()
    {
        var b = new SolidColorBrush(Color.FromRgb(0x1A, 0x1F, 0x2C));
        b.Freeze();
        return b;
    }

    private void UpdateSpin()
    {
        BeginAnimation(SpinProperty, IsIndeterminate
            ? new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.1)) { RepeatBehavior = RepeatBehavior.Forever }
            : null);
    }

    protected override void OnRender(DrawingContext dc)
    {
        double size = Math.Min(ActualWidth, ActualHeight);
        if (size <= 0) return;

        double t = Thickness;
        double radius = (size - t) / 2;
        var center = new Point(ActualWidth / 2, ActualHeight / 2);

        dc.DrawEllipse(null, new Pen(Track, t), center, radius, radius);

        double sweep = IsIndeterminate ? 90 : Math.Clamp(Value, 0, 100) * 3.6;
        if (sweep <= 0) return;

        var pen = new Pen(Stroke, t) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
        if (sweep >= 359.99)
        {
            dc.DrawEllipse(null, pen, center, radius, radius);
            return;
        }

        double start = -90 + (IsIndeterminate ? (double)GetValue(SpinProperty) : 0);
        Point PointAt(double deg)
        {
            double rad = deg * Math.PI / 180;
            return new Point(center.X + radius * Math.Cos(rad), center.Y + radius * Math.Sin(rad));
        }

        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(PointAt(start), false, false);
            ctx.ArcTo(PointAt(start + sweep), new Size(radius, radius), 0, sweep > 180, SweepDirection.Clockwise, true, false);
        }
        geometry.Freeze();
        dc.DrawGeometry(null, pen, geometry);
    }
}
