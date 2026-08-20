using System;
using Avalonia.Controls;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Avalonia.Services;

public class DialogService : VaultCrypt.Services.IDialogService
{
    
    public void ShowErrorWindow(Exception ex)
    {
        var window = new DialogWindow();
        var view = new Views.ExceptionThrown();
        var viewmodel = new ExceptionThrownViewModel(window.Close, ex);
        SetContent(window, view, viewmodel);
        window.ShowDialog(WindowHelper.GetCurrentWindow());
    }
    
    //Binds window with view and view with viewmodel
    private static void SetContent(Window window, UserControl view, IViewModel viewModel)
    {
        window.Content = view;
        view.DataContext = viewModel;
    }
}