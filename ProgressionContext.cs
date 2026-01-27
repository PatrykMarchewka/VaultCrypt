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
            Total = 0;
            CancellationTokenSource = new CancellationTokenSource();
            Progress = new Progress<ProgressStatus>(p => { Completed = p.completed; Total = p.total; });
        }
        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
    }
    public record ProgressStatus(int completed, int total);
}
