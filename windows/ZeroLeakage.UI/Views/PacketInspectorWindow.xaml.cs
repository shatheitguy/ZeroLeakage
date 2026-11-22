using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using ZeroLeakage.UI.Services.Dns;
using ZeroLeakage.UI.ViewModels;

namespace ZeroLeakage.UI.Views;

public partial class PacketInspectorWindow : Window
{
    private readonly PacketInspectorViewModel _vm;

    public PacketInspectorWindow(PacketInspectorViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        DataContext = vm;
        vm.PropertyChanged += OnVmChanged;
        Loaded += async (_, _) => await vm.RunAsync();
    }

    private void OnVmChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(PacketInspectorViewModel.Dnssec)) return;
        var (bg, line, fg) = _vm.Dnssec switch
        {
            DnssecStatus.Secure => ("Brush.MintSoft", "Brush.MintLine", "Brush.Mint"),
            DnssecStatus.Insecure => ("Brush.AmberSoft", "Brush.AmberLine", "Brush.Amber"),
            DnssecStatus.Bogus => ("Brush.CrimsonSoft", "Brush.CrimsonLine", "Brush.Crimson"),
            _ => ("Brush.Inset", "Brush.Border", "Brush.TextSecondary"),
        };
        DnssecBadge.Background = (Brush)FindResource(bg);
        DnssecBadge.BorderBrush = (Brush)FindResource(line);
        DnssecBadgeText.Foreground = (Brush)FindResource(fg);
    }

    private void OnHeaderDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape) Close();
        base.OnKeyDown(e);
    }
}
