using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
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

        private string _passwordString = null!;
        public string PasswordString
        {
            get => _passwordString;
            set
            {
                if(_passwordString == value) return;
                _passwordString = value;
                OnPropertyChanged(nameof(PasswordString));
            }
        }

        public ICommand GoBackCommand { get; }
        public ICommand OpenVaultCommand { get; }
        public PasswordInputViewModel()
        {
            GoBackCommand = new RelayCommand(_ => GoBack());
            OpenVaultCommand = new RelayCommand(_ => OpenVault());
        }

        public void GoBack()
        {
            _passwordBuffer?.Dispose();
            NavigationRequested?.Invoke(new NavigateToMainRequest());
        }

        public void OpenVault()
        {
            ValidationHelper.NotEmptyString(PasswordString, "Password");
            RecievePasswordString(PasswordString);

            NavigationRequested.Invoke(new NavigateToOpenVaultRequest(_passwordBuffer!, _vaultPath));
        }

        public void OnNavigatedTo(object parameters)
        {
            ArgumentNullException.ThrowIfNull(parameters);
            if (parameters is not NormalizedPath path) throw new ArgumentException("Couldnt cast from object to NormalizedPath");
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            this._vaultPath = path;
        }
        
        //Clears PasswordString and forces garbage collection to clear the data
        private void ClearPasswordString()
        {
            PasswordString = string.Empty;
            
            GC.Collect(generation: 2, GCCollectionMode.Forced, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
        }
        
        //Disposes previous password buffer and creates new one holding password
        private void RecievePasswordString(string password)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(password);

            _passwordBuffer?.Dispose();
            _passwordBuffer = SecureBuffer.StringToSecureBuffer(password);
            ClearPasswordString();
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
