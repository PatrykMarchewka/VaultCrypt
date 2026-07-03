using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Services
{
    internal interface IDialogService
    {
        /// <summary>
        /// Shows new <see cref="DialogWindow"/> with information about the <paramref name="ex"/>
        /// </summary>
        /// <param name="ex">Exception to show</param>
        public void ShowErrorWindow(Exception ex);
    }


    internal class DialogService : IDialogService
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
}
