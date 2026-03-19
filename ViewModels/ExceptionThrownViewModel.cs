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
    public class ExceptionThrownViewModel : INotifyPropertyChanged, INavigated, IViewModel, INavigatingViewModel
    {
        private string _exceptionMessage = null!;
        public string ExceptionMessage
        {
            get => _exceptionMessage;
            set
            {
                if (_exceptionMessage == value) return;
                _exceptionMessage = value;
                OnPropertyChanged(nameof(ExceptionMessage));
            }
        }

        public ICommand OKCommand { get; private set; } = null!;

        public ExceptionThrownViewModel(Exception? passedException = null)
        {
            Initialize(() => NavigationRequested?.Invoke(new NavigateToMainRequest()), passedException);
        }

        public ExceptionThrownViewModel(Action OKAction, Exception? passedException = null)
        {
            Initialize(OKAction, passedException);
        }

        private void Initialize(Action action, Exception? ex)
        {
            OnNavigatedTo(ex);
            OKCommand = new RelayCommand(_ => action());
        }

        public void OnNavigatedTo(object? parameters)
        {
            this.ExceptionMessage = (parameters as Exception)?.Message ?? "Unknown error!";
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
