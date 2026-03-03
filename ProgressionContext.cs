using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    public class ProgressionContext : INotifyPropertyChanged
    {
        private int _completed;
        public int Completed
        {
            get => _completed;
            set
            {
                if (_completed == value) return;
                _completed = value;
                OnPropertyChanged(nameof(Completed));
            }
        }
        private int _total;
        public int Total
        {
            get => _total;
            set
            {
                if (_total == value) return;
                _total = value;
                OnPropertyChanged(nameof(Total));
            }
        }
        public IProgress<ProgressStatus> Progress { get; init; }
        public CancellationTokenSource CancellationTokenSource;



        public CancellationToken CancellationToken => CancellationTokenSource.Token;

        public ProgressionContext()
        {
            Completed = 0;
            Total = 1; //Starting at 1 so user sees 0/1 instead 0/0
            CancellationTokenSource = new CancellationTokenSource();
            Progress = new Progress<ProgressStatus>(p => { Completed = p.Completed; Total = p.Total; });
        }
        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
    }
    public record ProgressStatus
    {
        public int Completed { get; }
        public int Total { get; }

        public ProgressStatus(int completed, int total)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(completed);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(total);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(completed, total);

            Completed = completed;
            Total = total;
        }
    }
}
