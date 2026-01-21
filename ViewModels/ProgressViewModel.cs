using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    class ProgressViewModel : INotifyPropertyChanged, INavigated, IViewModel, INavigatingViewModel
    {
        private VaultHelper.ProgressionContext _context;
        public VaultHelper.ProgressionContext Context
        {
            get => _context;
            set
            {
                if (_context == value) return;
                if(_context != null) _context.PropertyChanged -= _context_PropertyChanged;
                _context = value;
                _context.PropertyChanged += _context_PropertyChanged;
                OnPropertyChanged(nameof(Context));
            }
        }

        

        public ICommand FinishCommand { get; }
        public ICommand CancelCommand { get; }
        public ProgressViewModel()
        {
            FinishCommand = new RelayCommand(_ => Finish(), _ => (Context.Completed == Context.Total && Context.Completed != 0));
            CancelCommand = new RelayCommand(_ => Cancel(), _ => (Context.Completed != Context.Total || Context.Completed == 0));
        }

        private void Finish()
        {
            NavigateBack();
        }

        private void Cancel()
        {
            Context.CancellationTokenSource.Cancel();
            NavigateBack();
        }

        private void NavigateBack()
        {
            NavigationRequested?.Invoke(new NavigateToMainRequest());
        }

        private void _context_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            CalculateCanExecute();
        }

        private void CalculateCanExecute()
        {
            ((RelayCommand)FinishCommand).RaiseCanExecuteChanged();
            ((RelayCommand)CancelCommand).RaiseCanExecuteChanged();
        }

        public void OnNavigatedTo(object? parameters)
        {
            Context = (VaultHelper.ProgressionContext)parameters!;
        }



        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested;
    }
}
