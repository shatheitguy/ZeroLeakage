using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace ZeroLeakage.UI.Controls;

/// <summary>Bento metric tile: icon + title + badge, a big mono value, and a footer stat.</summary>
public partial class MetricCard : UserControl
{
    public MetricCard() => InitializeComponent();

    private static DependencyProperty Register<T>(string name, T fallback)
        => DependencyProperty.Register(name, typeof(T), typeof(MetricCard), new PropertyMetadata(fallback));

    public static readonly DependencyProperty TitleProperty = Register("Title", "");
    public static readonly DependencyProperty GlyphProperty = Register("Glyph", "");
    public static readonly DependencyProperty ValueProperty = Register("Value", "");
    public static readonly DependencyProperty UnitProperty = Register("Unit", "");
    public static readonly DependencyProperty CaptionProperty = Register("Caption", "");
    public static readonly DependencyProperty SecondaryValueProperty = Register("SecondaryValue", "");
    public static readonly DependencyProperty BadgeProperty = Register("Badge", "");
    public static readonly DependencyProperty AccentProperty = Register<Brush>("Accent", Brushes.White);

    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public string Glyph { get => (string)GetValue(GlyphProperty); set => SetValue(GlyphProperty, value); }
    public string Value { get => (string)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public string Unit { get => (string)GetValue(UnitProperty); set => SetValue(UnitProperty, value); }
    public string Caption { get => (string)GetValue(CaptionProperty); set => SetValue(CaptionProperty, value); }
    public string SecondaryValue { get => (string)GetValue(SecondaryValueProperty); set => SetValue(SecondaryValueProperty, value); }
    public string Badge { get => (string)GetValue(BadgeProperty); set => SetValue(BadgeProperty, value); }
    public Brush Accent { get => (Brush)GetValue(AccentProperty); set => SetValue(AccentProperty, value); }
}
