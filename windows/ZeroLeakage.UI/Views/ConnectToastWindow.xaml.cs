using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using ZeroLeakage.UI.ViewModels;

namespace ZeroLeakage.UI.Views;

/// <summary>Bottom-right dark-glass toast that slides in when an unapproved .exe tries to connect.</summary>
public partial class ConnectToastWindow : Window
{
    private readonly ConnectToastViewModel _vm;
    private bool _closing;

    public ConnectToastWindow(ConnectToastViewModel vm)
    {
        InitializeComponent();
        DataContext = _vm = vm;

        if (!vm.Request.IsSigned)
        {
            Sig.Background = (Brush)FindResource("Brush.CrimsonSoft");
            Sig.BorderBrush = (Brush)FindResource("Brush.CrimsonLine");
            SigText.Foreground = (Brush)FindResource("Brush.Crimson");
        }

        vm.Decided += (_, _) => SlideOut();
        Loaded += (_, _) => { PositionBottomRight(); SlideIn(); };
        SizeChanged += (_, _) => PositionBottomRight();
    }

    private void PositionBottomRight()
    {
        var area = SystemParameters.WorkArea;
        Left = area.Right - ActualWidth;
        Top = area.Bottom - ActualHeight;
    }

    private void SlideIn()
    {
        var d = TimeSpan.FromMilliseconds(380);
        var ease = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.25 };
        Slide.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(440, 0, d) { EasingFunction = ease });
        Root.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));
    }

    private void SlideOut()
    {
        if (_closing) return;
        _closing = true;
        var d = TimeSpan.FromMilliseconds(240);
        var anim = new DoubleAnimation(0, 440, d) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn } };
        anim.Completed += (_, _) => Close();
        Slide.BeginAnimation(TranslateTransform.XProperty, anim);
        Root.BeginAnimation(OpacityProperty, new DoubleAnimation(1, 0, d));
    }
}
