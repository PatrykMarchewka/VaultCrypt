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
    internal class PasswordInputViewModel : INotifyPropertyChanged, INavigated, IViewModel, INavigatingViewModel
    {
        internal NormalizedPath? vaultPath;

        private SecureString _password;
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
        internal PasswordInputViewModel()
        {
            GoBackCommand = new RelayCommand(_ => NavigationRequested?.Invoke(new NavigateToMainRequest()));
            OpenVaultCommand = new RelayCommand(_ => OpenVault());
        }

        private void OpenVault()
        {
            if (Password == null  || Password.Length == 0)
            {
                throw new Exception("Password is empty");
            }
            else
            {
                NavigationRequested?.Invoke(new NavigateToOpenVaultRequest(Password, VaultPath));
                this.Password.Clear();
            }

        }

        


        public void OnNavigatedTo(object? parameters)
        {
            this.vaultPath = NormalizedPath.From((string)parameters!);
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested;
    }
}
