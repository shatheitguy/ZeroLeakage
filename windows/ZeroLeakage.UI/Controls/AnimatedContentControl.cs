using System;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace ZeroLeakage.UI.Controls;

/// <summary>ContentControl that fades + lifts new content in (page transitions).</summary>
public sealed class AnimatedContentControl : ContentControl
{
    private readonly TranslateTransform _shift = new();

    public AnimatedContentControl()
    {
        RenderTransform = _shift;
        Focusable = false;
        IsTabStop = false;
    }

    protected override void OnContentChanged(object oldContent, object newContent)
    {
        base.OnContentChanged(oldContent, newContent);
        if (oldContent is null || newContent is null) return;

        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        var duration = TimeSpan.FromMilliseconds(280);
        BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, duration) { EasingFunction = ease });
        _shift.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(12, 0, duration) { EasingFunction = ease });
    }
}
