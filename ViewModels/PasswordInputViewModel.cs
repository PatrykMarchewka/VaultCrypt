using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace VaultCrypt.ViewModels
{
    internal class PasswordInputViewModel : INotifyPropertyChanged, INavigated, IViewModel
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
        internal PasswordInputViewModel(INavigationService nav)
        {
            GoBackCommand = new RelayCommand(_ => nav.NavigateToMain());
            OpenVaultCommand = new RelayCommand(_ => OpenVault(nav));
        }

        private void OpenVault(INavigationService nav)
        {
            if (Password == null  || Password.Length == 0)
            {
                throw new Exception("Password is empty");
            }
            else
            {
                nav.NavigateToOpenVault(Password, vaultPath!);
            }

        }

        


        public void OnNavigatedTo(object? parameters)
        {
            this.vaultPath = NormalizedPath.From((string)parameters!);
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
    }
}
