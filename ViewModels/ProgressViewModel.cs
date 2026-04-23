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
    public class ProgressViewModel : INotifyPropertyChanged, INavigated, IViewModel, INavigatingViewModel
    {
        private ProgressionContext _context = null!;
        public ProgressionContext Context
        {
            get => _context;
            set
            {
                if (_context == value) return;
                _context = value;
                _context.Progress = _progress;
                CalculateCanExecute();
                OnPropertyChanged(nameof(Context));
            }
        }

        private IProgress<ProgressionContext> _progress;
        private IProgress<ProgressReported> _progress;

        public ICommand FinishCommand { get; }
        public ICommand CancelCommand { get; }
        public ProgressViewModel()
        {
            _progress = new Progress<ProgressReported>(status =>
            {
                //Runs everytime _progress.Report() is called
                OnPropertyChanged(nameof(Context));
                CalculateCanExecute();
            });
            FinishCommand = new RelayCommand(_ => Finish(), _ => (Context.Completed == Context.Total));
            CancelCommand = new RelayCommand(_ => Cancel(), _ => (Context.Completed != Context.Total));
        }

        public void Finish()
        {
            NavigateBack();
        }

        public void Cancel()
        {
            Context.Cancel();
            NavigateBack();
        }

        public void NavigateBack()
        {
            NavigationRequested?.Invoke(new NavigateFromProgressRequest());
        }

        private void CalculateCanExecute()
        {
            ((RelayCommand)FinishCommand).RaiseCanExecuteChanged();
            ((RelayCommand)CancelCommand).RaiseCanExecuteChanged();
        }

        public void OnNavigatedTo(object? parameters)
        {
            Context = (ProgressionContext)parameters!;
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
