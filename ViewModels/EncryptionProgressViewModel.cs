using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace VaultCrypt.ViewModels
{
    class EncryptionProgressViewModel : INotifyPropertyChanged, INavigated, IViewModel
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
        public EncryptionProgressViewModel(INavigationService nav)
        {
            FinishCommand = new RelayCommand(_ => Finish(nav), _ => (Context.Completed == Context.Total && Context.Completed != 0));
            CancelCommand = new RelayCommand(_ => Cancel(nav), _ => (Context.Completed != Context.Total || Context.Completed == 0));
        }

        private void Finish(INavigationService nav)
        {
            NavigateBack(nav);
        }

        private void Cancel(INavigationService nav)
        {
            Context.CancellationTokenSource.Cancel();
            NavigateBack(nav);
        }

        private void NavigateBack(INavigationService nav)
        {
            nav.NavigateFromProgress();
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
    }
}
