using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace VaultCrypt.ViewModels
{
    internal class MainViewViewModel : INotifyPropertyChanged
    {


        public ICommand CreateVaultCommand { get; }
        public ICommand OpenVaultCommand { get; }

        internal MainViewViewModel(INavigationService nav)
        {
            CreateVaultCommand = new RelayCommand(_ => nav.NavigateToCreateVault());
            OpenVaultCommand = new RelayCommand(_ => SelectVaultFilePickerOpen(nav));
        }

        internal void SelectVaultFilePickerOpen(INavigationService nav)
        {
            string? path = FileHelper.OpenFile("Select vault file");
            if (path != null)
            {
                nav.NavigateToPasswordInput(path);
            }

        }



        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
    }
}
