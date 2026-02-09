using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace VaultCrypt.ViewModels
{
    internal class MainViewViewModel : INotifyPropertyChanged, IViewModel, INavigatingViewModel
    {
        public ICommand CreateVaultCommand { get; }
        public ICommand OpenVaultCommand { get; }

        internal MainViewViewModel()
        {
            CreateVaultCommand = new RelayCommand(_ => NavigationRequested?.Invoke(new NavigateToCreateVaultRequest()));
            OpenVaultCommand = new RelayCommand(_ => SelectVaultFilePickerOpen());
        }

        internal void SelectVaultFilePickerOpen()
        {
            NormalizedPath? path = NormalizedPath.From(FileDialogHelper.OpenFile("Select vault file", false));
            if (path != null)
            {
                NavigationRequested?.Invoke(new NavigateToPasswordInputRequest(path));
            }

        }



        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
