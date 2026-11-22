using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace ZeroLeakage.UI.Interop;

/// <summary>DWM tweaks for the frameless window: dark frame, rounded corners, tinted 1px border.</summary>
internal static class WindowEffects
{
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWA_BORDER_COLOR = 34;
    private const int DWMWA_CAPTION_COLOR = 35;
    private const int DWMWCP_ROUND = 2;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    public static void Apply(Window window, uint borderRgb = 0x1F2433, uint captionRgb = 0x090A0F)
    {
        var hwnd = new WindowInteropHelper(window).EnsureHandle();
        Set(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, 1);
        Set(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND);
        Set(hwnd, DWMWA_BORDER_COLOR, ToColorRef(borderRgb));
        Set(hwnd, DWMWA_CAPTION_COLOR, ToColorRef(captionRgb));
    }

    // Win32 COLORREF is 0x00BBGGRR.
    private static int ToColorRef(uint rgb) => (int)(((rgb & 0xFF) << 16) | (rgb & 0xFF00) | ((rgb >> 16) & 0xFF));

    private static void Set(IntPtr hwnd, int attr, int value)
    {
        try { DwmSetWindowAttribute(hwnd, attr, ref value, sizeof(int)); }
        catch { /* Older Windows builds: attribute unsupported — keep defaults. */ }
    }
}
