using System;
using System.Windows;
using System.Windows.Controls;
using VaultCrypt.Services;
using VaultCrypt.ViewModels;

namespace VaultCrypt.WPF.Services;

internal sealed class DialogService : IDialogService
{
    public void ShowErrorWindow(Exception ex)
    {
        var window = new DialogWindow();
        var view = new Views.ExceptionThrown();
        var vm = new ExceptionThrownViewModel(OKAction: () => window.Close(), passedException: ex);
        SetContent(window, view, vm);
        window.ShowDialog();
    }

    //Binds window with view and view with viewmodel
    private static void SetContent(Window window, UserControl view, IViewModel viewModel)
    {
        window.Content = view;
        view.DataContext = viewModel;
    }
}