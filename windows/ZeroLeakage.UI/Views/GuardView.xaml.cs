using System.Windows;
using System.Windows.Controls;
using ZeroLeakage.UI.ViewModels;

namespace ZeroLeakage.UI.Views;

public partial class GuardView : UserControl
{
    public GuardView() => InitializeComponent();

    // PasswordBox can't bind; hand the key to the view-model only when it changes, clear it after saving.
    private void OnKeyChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is GuardViewModel vm) vm.ServerKey = KeyBox.Password;
    }

    private void OnSaveClicked(object sender, RoutedEventArgs e) =>
        Dispatcher.BeginInvoke(() => KeyBox.Clear(), System.Windows.Threading.DispatcherPriority.Background);
}
