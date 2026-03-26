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
        private ulong _completed;
        public ulong Completed
        {
            get => _completed;
            set
            {
                if (_completed == value) return;
                _completed = value;
                OnPropertyChanged(nameof(Completed));
            }
        }
        private ulong _total;
        public ulong Total
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
        public ulong Completed { get; }
        public ulong Total { get; }

        public ProgressStatus(ulong completed, ulong total)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(completed);
            ArgumentOutOfRangeException.ThrowIfZero(total);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(completed, total);

            Completed = completed;
            Total = total;
        }

        public ProgressStatus(int completed, int total) : this((ulong) completed, (ulong)total)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(total);
        }
    }
}
