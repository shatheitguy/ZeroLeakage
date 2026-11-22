using System;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.Mvvm;

namespace ZeroLeakage.UI.ViewModels;

public sealed class ConnectToastViewModel : ObservableObject
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly DispatcherTimer _timer;
    private readonly DateTime _shownAt = DateTime.Now;
    private bool _decided;

    public ConnectToastViewModel(ConnectionRequest request)
    {
        Request = request;
        AppIcon = TryLoadIcon(request.ProcessPath);

        AllowCommand = new RelayCommand(() => Decide(ConnectDecision.Allow));
        AllowOnceCommand = new RelayCommand(() => Decide(ConnectDecision.AllowOnce));
        BlockCommand = new RelayCommand(() => Decide(ConnectDecision.Block));

        // Default-deny: no answer within 30 s means Block.
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _timer.Tick += (_, _) =>
        {
            OnPropertyChanged(nameof(Remaining));
            OnPropertyChanged(nameof(CountdownText));
            if (DateTime.Now - _shownAt >= Timeout) Decide(ConnectDecision.Block);
        };
        _timer.Start();
    }

    public ConnectionRequest Request { get; }
    public ImageSource? AppIcon { get; }
    public bool HasIcon => AppIcon is not null;
    public string Initial => Request.ProcessName.Length > 0 ? Request.ProcessName[..1].ToUpperInvariant() : "?";
    public string SignatureText => Request.IsSigned ? $"✓ Signed · {Request.Publisher}" : "⚠ Unsigned binary";
    public string EndpointText => $"{Request.RemoteIp}:{Request.Port} · {Request.Protocol}";

    public double Remaining => Math.Clamp(1 - (DateTime.Now - _shownAt).TotalMilliseconds / Timeout.TotalMilliseconds, 0, 1);
    public string CountdownText => $"auto-block in {Math.Max(0, (int)Math.Ceiling((Timeout - (DateTime.Now - _shownAt)).TotalSeconds))}s";

    public ICommand AllowCommand { get; }
    public ICommand AllowOnceCommand { get; }
    public ICommand BlockCommand { get; }

    public event EventHandler<ConnectDecision>? Decided;

    private void Decide(ConnectDecision decision)
    {
        if (_decided) return;
        _decided = true;
        _timer.Stop();
        Decided?.Invoke(this, decision);
    }

    private static ImageSource? TryLoadIcon(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (icon is null) return null;
            var src = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            src.Freeze();
            return src;
        }
        catch
        {
            return null;
        }
    }
}
