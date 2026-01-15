using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace VaultCrypt.ViewModels
{
    internal class MainWindowViewModel : INotifyPropertyChanged, INavigationService, IViewModel
    {
        private IViewModel _currentView;
        public IViewModel CurrentView
        {
            get => _currentView;
            set
            {
                _currentView = value;
                OnPropertyChanged(nameof(CurrentView));
            }
        }

        private readonly MainViewViewModel _mainViewViewModel;
        private readonly CreateVaultViewModel _createVaultViewModel;
        private readonly OpenVaultViewModel _openVaultViewModel;
        private readonly PasswordInputViewModel _passwordInputViewModel;
        private readonly EncryptFileViewModel _encryptFileViewModel;
        internal MainWindowViewModel()
        {
            _mainViewViewModel = new MainViewViewModel(this);
            _createVaultViewModel = new CreateVaultViewModel(this);
            _openVaultViewModel = new OpenVaultViewModel(this);
            _passwordInputViewModel = new PasswordInputViewModel(this);
            _encryptFileViewModel = new EncryptFileViewModel(this);

            CurrentView = _mainViewViewModel;
        }

        private void Navigate(IViewModel viewModel, object? parameters = null)
        {
            if (viewModel is INavigated nav && parameters != null)
            {
                nav.OnNavigatedTo(parameters);
            }
            CurrentView = viewModel;
        }
        public void NavigateToMain()
        {
            Navigate(_mainViewViewModel);
        }

        public void NavigateToCreateVault()
        {
            Navigate(_createVaultViewModel);
        }

        public void NavigateToOpenVault(SecureString password, string vaultPath)
        {
            Navigate(_openVaultViewModel, new { Password = password, VaultPath = vaultPath });
        }

        public void NavigateToPasswordInput(string vaultPath)
        {
            Navigate(_passwordInputViewModel, vaultPath);
        }

        public void NavigateToEncryptFile(NormalizedPath filePath)
        {
            Navigate(_encryptFileViewModel, filePath);
        }
        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
    }
}
