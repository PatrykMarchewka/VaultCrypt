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
        private object _currentView;
        public object CurrentView
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
        internal MainWindowViewModel()
        {
            _mainViewViewModel = new MainViewViewModel(this);
            _createVaultViewModel = new CreateVaultViewModel(this);

            CurrentView = _mainViewViewModel;
        }

        public void NavigateToMain()
        {
            CurrentView = _mainViewViewModel;
        }

        public void NavigateToCreateVault()
        {
            CurrentView = _createVaultViewModel;
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
    }
}
