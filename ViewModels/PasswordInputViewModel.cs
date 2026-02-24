using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    public class PasswordInputViewModel : INotifyPropertyChanged, INavigated, IViewModel, INavigatingViewModel
    {
        private NormalizedPath? VaultPath;

        private SecureString _password = null!;
        public SecureString Password
        {
            get => _password;
            set
            {
                if (_password == value) return;
                _password = value;
                OnPropertyChanged(nameof(Password));
            }
        }

        public ICommand GoBackCommand { get; }
        public ICommand OpenVaultCommand { get; }
        public PasswordInputViewModel()
        {
            GoBackCommand = new RelayCommand(_ => NavigationRequested?.Invoke(new NavigateToMainRequest()));
            OpenVaultCommand = new RelayCommand(_ => OpenVault());
        }

        public void OpenVault()
        {
            ValidationHelper.NotEmptySecureString(Password, "Password");

            NavigationRequested?.Invoke(new NavigateToOpenVaultRequest(Password, VaultPath!));
            this.Password.Clear();
        }

        public void OnNavigatedTo(object? parameters)
        {
            this.VaultPath = (NormalizedPath)parameters!;
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
