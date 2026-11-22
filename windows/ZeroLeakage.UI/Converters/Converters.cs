using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace ZeroLeakage.UI.Converters;

public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value is true ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => value is Visibility.Collapsed;
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value is not true;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => value is not true;
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type t, object p, CultureInfo c) => value is null ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>Visible when an int/long count is zero (empty states).</summary>
public sealed class ZeroToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c)
        => System.Convert.ToInt64(value, CultureInfo.InvariantCulture) == 0 ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>Binds an enum to a RadioButton: IsChecked="{Binding Mode, Converter=..., ConverterParameter=Value}".</summary>
public sealed class EnumEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => value is not null && p is not null && string.Equals(value.ToString(), p.ToString(), StringComparison.OrdinalIgnoreCase);

    public object ConvertBack(object value, Type targetType, object? p, CultureInfo c)
    {
        if (value is true && p is not null)
        {
            var enumType = Nullable.GetUnderlyingType(targetType) ?? targetType;
            return enumType.IsEnum
                ? Enum.Parse(enumType, p.ToString()!, true)
                : System.Convert.ChangeType(p, enumType, CultureInfo.InvariantCulture);
        }
        return Binding.DoNothing;
    }
}

/// <summary>Visible when value.ToString() equals the parameter (wizard steps).</summary>
public sealed class EqualsToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => string.Equals(value?.ToString(), p?.ToString(), StringComparison.Ordinal) ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotSupportedException();
}
