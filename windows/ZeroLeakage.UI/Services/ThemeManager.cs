using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using ZeroLeakage.UI.Models;

namespace ZeroLeakage.UI.Services;

/// <summary>
/// Owns the mode-reactive accent brushes. They are created in code (never frozen) and installed
/// at the top of Application.Resources, so every DynamicResource consumer cross-fades smoothly
/// between Mint (Balanced), Violet (Strict Guard) and Crimson (Total Zero-Leak).
/// </summary>
public static class ThemeManager
{
    public static readonly Color Mint = Color.FromRgb(0x00, 0xF5, 0xA0);
    public static readonly Color Violet = Color.FromRgb(0x7B, 0x61, 0xFF);
    public static readonly Color Crimson = Color.FromRgb(0xFF, 0x2E, 0x54);

    private static readonly SolidColorBrush Accent = new(Mint);
    private static readonly SolidColorBrush AccentSoft = new(WithAlpha(Mint, 0x26));
    private static readonly SolidColorBrush AccentFaint = new(WithAlpha(Mint, 0x10));

    public static Color ColorFor(ProtectionMode mode) => mode switch
    {
        ProtectionMode.StrictGuard => Violet,
        ProtectionMode.TotalLockdown => Crimson,
        _ => Mint,
    };

    public static Color WithAlpha(Color c, byte a) => Color.FromArgb(a, c.R, c.G, c.B);

    public static void Initialize(ResourceDictionary resources, ProtectionMode mode)
    {
        resources["Brush.ModeAccent"] = Accent;
        resources["Brush.ModeAccentSoft"] = AccentSoft;
        resources["Brush.ModeAccentFaint"] = AccentFaint;
        Apply(mode, animate: false);
    }

    public static void Apply(ProtectionMode mode, bool animate = true)
    {
        var c = ColorFor(mode);
        Animate(Accent, c, animate);
        Animate(AccentSoft, WithAlpha(c, 0x26), animate);
        Animate(AccentFaint, WithAlpha(c, 0x10), animate);
        if (Application.Current is { } app) app.Resources["Color.ModeAccent"] = c;
    }

    private static void Animate(SolidColorBrush brush, Color to, bool animate)
    {
        if (brush.IsFrozen) return;
        if (!animate)
        {
            brush.BeginAnimation(SolidColorBrush.ColorProperty, null);
            brush.Color = to;
            return;
        }
        brush.BeginAnimation(SolidColorBrush.ColorProperty,
            new ColorAnimation(to, TimeSpan.FromMilliseconds(450)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
    }
}
