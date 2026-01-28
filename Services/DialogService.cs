using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using VaultCrypt.Exceptions;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Services
{
    internal interface IDialogService
    {
        void ShowWindow(UserControl view, IViewModel viewModel);
        void ShowErrorWindow(Exception ex);
    }


    internal class DialogService : IDialogService
    {
        public void ShowWindow(UserControl view, IViewModel viewModel)
        {
            var window = new DialogWindow();
            SetContent(window, view, viewModel);
            window.ShowDialog();
        }

        public void ShowErrorWindow(Exception ex)
        {
            var window = new DialogWindow();
            var view = new Views.ExceptionThrown();
            var vm = new ExceptionThrownViewModel(() => window.Close(), ex);
            SetContent(window, view, vm);
            window.Show();
        }

        private void SetContent(Window window, UserControl view, IViewModel viewModel)
        {
            window.Content = view;
            window.DataContext = viewModel;
        }
    }
}
