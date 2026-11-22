using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.ViewModels;
using WinForms = System.Windows.Forms;

namespace ZeroLeakage.UI.Services;

/// <summary>System-tray presence: protection keeps running while the window is hidden.</summary>
public sealed class TrayIconService : IDisposable
{
    private readonly WinForms.NotifyIcon _icon;
    private readonly MainWindow _window;
    private readonly MainViewModel _shell;
    private readonly WinForms.ToolStripMenuItem[] _modeItems;
    private IntPtr _hIcon;

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);

    public TrayIconService(MainWindow window, MainViewModel shell, Action exit)
    {
        _window = window;
        _shell = shell;

        var menu = new WinForms.ContextMenuStrip { Renderer = new DarkRenderer(), ShowImageMargin = false, ShowCheckMargin = true };
        menu.Items.Add("Open ZeroLeakage", null, (_, _) => _window.ShowFromTray());
        menu.Items.Add(new WinForms.ToolStripSeparator());
        _modeItems = new[]
        {
            new WinForms.ToolStripMenuItem("01 // Balanced Shield", null, (_, _) => SetMode(ProtectionMode.Balanced)),
            new WinForms.ToolStripMenuItem("02 // Strict Guard", null, (_, _) => SetMode(ProtectionMode.StrictGuard)),
            new WinForms.ToolStripMenuItem("03 // Total Zero-Leak", null, (_, _) => SetMode(ProtectionMode.TotalLockdown)),
        };
        menu.Items.AddRange(_modeItems);
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Exit (stops protection UI)", null, (_, _) => exit());
        foreach (WinForms.ToolStripItem item in menu.Items) item.ForeColor = Color.FromArgb(0xF2, 0xF4, 0xF8);

        _icon = new WinForms.NotifyIcon
        {
            Icon = CreateIcon(),
            Text = "ZeroLeakage — zero bits leaked",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.DoubleClick += (_, _) => _window.ShowFromTray();
        _icon.MouseClick += (_, e) => { if (e.Button == WinForms.MouseButtons.Left) _window.ShowFromTray(); };

        _shell.ModeChanged += (_, _) => SyncChecks();
        SyncChecks();
    }

    private void SetMode(ProtectionMode mode) => _shell.Mode = mode;

    private void SyncChecks()
    {
        for (int i = 0; i < _modeItems.Length; i++) _modeItems[i].Checked = (int)_shell.Mode == i + 1;
        _icon.Text = $"ZeroLeakage — {_shell.ModeLabel}";
    }

    /// <summary>
    /// Draws the shield brand mark (dark rounded tile, mint shield, slashed zero cut out) so it reads on both
    /// light and dark taskbars and no binary asset is needed at runtime. Geometry matches tools/New-AppIcon.ps1.
    /// </summary>
    private Icon CreateIcon()
    {
        int size = Math.Max(16, WinForms.SystemInformation.SmallIconSize.Width * 2);
        using var bmp = new Bitmap(size, size);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.Clear(Color.Transparent);
            var tile = Color.FromArgb(0x12, 0x15, 0x1E);
            float s = size / 96f;
            using (var tilePath = RoundRect(0, 0, size - 1, size - 1, 22 * s))
            using (var tileBrush = new SolidBrush(tile))
                g.FillPath(tileBrush, tilePath);

            // Slightly enlarged shield so it stays legible at 16-20 px.
            float k = s * 1.2f, o = size / 2f - 48 * k;
            PointF P(float x, float y) => new(o + x * k, o + y * k);
            using var shield = new GraphicsPath();
            shield.AddLine(P(48, 16), P(74, 26));
            shield.AddLine(P(74, 26), P(74, 48));
            shield.AddBezier(P(74, 48), P(74, 64), P(62, 74), P(48, 80));
            shield.AddBezier(P(48, 80), P(34, 74), P(22, 64), P(22, 48));
            shield.AddLine(P(22, 48), P(22, 26));
            shield.CloseFigure();
            using (var mint = new SolidBrush(Color.FromArgb(0x00, 0xF5, 0xA0))) g.FillPath(mint, shield);
            using (var ring = new Pen(tile, 6 * k)) g.DrawEllipse(ring, o + 38 * k, o + 32 * k, 20 * k, 30 * k);
            using (var slash = new Pen(tile, 4 * k) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                g.DrawLine(slash, P(40, 58), P(56, 36));
        }
        _hIcon = bmp.GetHicon();
        return Icon.FromHandle(_hIcon);
    }

    private static GraphicsPath RoundRect(float x, float y, float w, float h, float r)
    {
        var p = new GraphicsPath();
        float d = 2 * r;
        p.AddArc(x, y, d, d, 180, 90);
        p.AddArc(x + w - d, y, d, d, 270, 90);
        p.AddArc(x + w - d, y + h - d, d, d, 0, 90);
        p.AddArc(x, y + h - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    /// <summary>One-time tip shown the first time the window is closed to the tray.</summary>
    public void ShowStillRunningHint() =>
        _icon.ShowBalloonTip(5000, "ZeroLeakage is still protecting you",
            "It keeps running in the background. Open it from this icon; use Exit in its menu to stop it.",
            WinForms.ToolTipIcon.None);

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        if (_hIcon != IntPtr.Zero) DestroyIcon(_hIcon);
    }

    private sealed class DarkRenderer : WinForms.ToolStripProfessionalRenderer
    {
        public DarkRenderer() : base(new DarkColors()) { RoundedEdges = false; }

        protected override void OnRenderItemText(WinForms.ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = Color.FromArgb(0xF2, 0xF4, 0xF8);
            base.OnRenderItemText(e);
        }
    }

    private sealed class DarkColors : WinForms.ProfessionalColorTable
    {
        private static readonly Color Surface = Color.FromArgb(0x12, 0x15, 0x1E);
        private static readonly Color Hover = Color.FromArgb(0x1F, 0x24, 0x33);
        private static readonly Color Line = Color.FromArgb(0x2A, 0x31, 0x45);
        public override Color ToolStripDropDownBackground => Surface;
        public override Color MenuBorder => Line;
        public override Color MenuItemBorder => Hover;
        public override Color MenuItemSelected => Hover;
        public override Color SeparatorDark => Line;
        public override Color SeparatorLight => Line;
        public override Color CheckBackground => Hover;
        public override Color CheckSelectedBackground => Hover;
        public override Color CheckPressedBackground => Hover;
        public override Color ImageMarginGradientBegin => Surface;
        public override Color ImageMarginGradientMiddle => Surface;
        public override Color ImageMarginGradientEnd => Surface;
    }
}
