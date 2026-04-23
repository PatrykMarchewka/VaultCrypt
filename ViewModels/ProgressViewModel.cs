using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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

        public ObservableCollection<string> PermMessages { get; } = new ObservableCollection<string>();

        private string _tempMessage = string.Empty;
        public string TempMessage => _tempMessage;

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
                AddPermMessage(status.Message);
                SetTempMessage(status.TempMessage);
            });
            FinishCommand = new RelayCommand(_ => Finish(), _ => (Context.Completed == Context.Total));
            CancelCommand = new RelayCommand(_ => Cancel(), _ => (Context.Completed != Context.Total));
        }

        private void AddPermMessage(string? message)
        {
            if (!string.IsNullOrEmpty(message)) PermMessages.Insert(0, message);
        }

        private void SetTempMessage(string? tempMessage)
        {
            if (!string.IsNullOrEmpty(tempMessage)) _tempMessage = tempMessage;
            else _tempMessage = string.Empty;
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
            Context.Dispose();
            PermMessages.Clear();
            _tempMessage = string.Empty;
            NavigationRequested?.Invoke(new NavigateFromProgressRequest());
        }

        private void CalculateCanExecute()
        {
            ((RelayCommand)FinishCommand).RaiseCanExecuteChanged();
            ((RelayCommand)CancelCommand).RaiseCanExecuteChanged();
        }

        public void OnNavigatedTo(object? parameters)
        {
            PermMessages.Clear();
            Context = (ProgressionContext)parameters!;
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
