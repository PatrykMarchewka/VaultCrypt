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
    public class PasswordInputViewModel : INotifyPropertyChanged, INavigatedViewModel, INavigatingViewModel
    {
        private NormalizedPath _vaultPath = null!;
        private ISecureBuffer? _passwordBuffer;

        public ICommand GoBackCommand { get; }
        public ICommand OpenVaultCommand { get; }
        public PasswordInputViewModel()
        {
            GoBackCommand = new RelayCommand(_ => NavigationRequested?.Invoke(new NavigateToMainRequest()));
            OpenVaultCommand = new RelayCommand(_ => OpenVault());
        }

        public void OpenVault()
        {
            ValidationHelper.NotEmptySecureBuffer(_passwordBuffer, "Password");

            NavigationRequested.Invoke(new NavigateToOpenVaultRequest(_passwordBuffer!, _vaultPath));
        }

        public void OnNavigatedTo(object parameters)
        {
            ArgumentNullException.ThrowIfNull(parameters);
            if (parameters is not NormalizedPath path) throw new ArgumentException("Couldnt cast from object to NormalizedPath");
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            this._vaultPath = path;
        }


        /// <summary>
        /// Disposes previous password buffer and creates new one from provided <paramref name="password"/>
        /// </summary>
        /// <param name="password">Password to use</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="password"/> is set to null</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is set to empty or whitespace only characters</exception>
        public void RecievePasswordString(string password)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(password);

            _passwordBuffer?.Dispose();
            _passwordBuffer = PasswordHelper.StringToSecureBuffer(password);
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
