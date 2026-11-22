using System;
using System.Windows;
using System.Windows.Media.Animation;

namespace ZeroLeakage.UI;

/// <summary>Animated launch splash: shield draws on, sonar rings pulse, scanning bar runs.</summary>
public partial class SplashWindow : Window
{
    public SplashWindow() => InitializeComponent();

    public void FadeOutAndClose()
    {
        var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(260));
        fade.Completed += (_, _) => Close();
        BeginAnimation(OpacityProperty, fade);
    }
}
