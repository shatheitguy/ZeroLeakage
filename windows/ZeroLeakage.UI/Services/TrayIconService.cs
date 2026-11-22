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

    /// <summary>Draws the hexagon + drop brand mark so no binary asset is required at runtime.</summary>
    private Icon CreateIcon()
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            var mint = Color.FromArgb(0x00, 0xF5, 0xA0);
            var hex = new PointF[6];
            for (int i = 0; i < 6; i++)
            {
                double a = Math.PI / 180 * (60 * i - 90);
                hex[i] = new PointF(16 + 14f * (float)Math.Cos(a), 16 + 14f * (float)Math.Sin(a));
            }
            using var fill = new SolidBrush(Color.FromArgb(0x09, 0x0A, 0x0F));
            g.FillPolygon(fill, hex);
            using var pen = new Pen(mint, 2.6f) { LineJoin = LineJoin.Round };
            g.DrawPolygon(pen, hex);
            using var drop = new SolidBrush(mint);
            g.FillEllipse(drop, 11.5f, 13f, 9f, 9f);
            g.FillPolygon(drop, new[] { new PointF(16, 7.5f), new PointF(20.2f, 15f), new PointF(11.8f, 15f) });
        }
        _hIcon = bmp.GetHicon();
        return Icon.FromHandle(_hIcon);
    }

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
