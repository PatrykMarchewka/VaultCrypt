using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    internal class EncryptFileViewModel : INotifyPropertyChanged, INavigated, IViewModel, INavigatingViewModel
    {
        private NormalizedPath filePath;
        public IReadOnlyList<ChunkSizePreset> ChunkSizePresets { get; } = [
            new(Name: "1MB", SizeInMB: 1),
            new(Name: "2MB", SizeInMB: 2),
            new(Name: "4MB", SizeInMB: 4),
            new(Name: "8MB", SizeInMB: 8),
            new(Name: "16MB", SizeInMB: 16),
            new(Name: "32MB", SizeInMB: 32),
            new(Name: "64MB", SizeInMB: 64),
            new(Name: "128MB", SizeInMB: 128),
            new(Name: "256MB", SizeInMB: 256),
            new(Name: "512MB", SizeInMB: 512),
            new(Name: "1024MB", SizeInMB: 1024),
            new(Name: "2048MB", SizeInMB: 2048)
            ];

        private ChunkSizePreset _selectedPreset;
        public ChunkSizePreset SelectedPreset
        {
            get => _selectedPreset;
            set
            {
                if (_selectedPreset == value) return;
                _selectedPreset = value;
                OnPropertyChanged(nameof(SelectedPreset));
            }
        }

        private EncryptionOptions.EncryptionProtocol _selectedProtocol;
        public EncryptionOptions.EncryptionProtocol SelectedProtocol
        {
            get => _selectedProtocol;
            set
            {
                if (_selectedProtocol == value) return;
                _selectedProtocol = value;
                OnPropertyChanged(nameof(SelectedProtocol));
            }
        }

        public Array EncryptionProtocolEnumValues => Enum.GetValues(typeof(EncryptionOptions.EncryptionProtocol));

        public ICommand GoBackCommand { get; }
        public ICommand EncryptCommand { get; }
        public EncryptFileViewModel()
        {
            SelectedPreset = ChunkSizePresets[0];

            GoBackCommand = new RelayCommand(_ => NavigationRequested?.Invoke(new NavigateToMainRequest()));
            EncryptCommand = new RelayCommand(_ => Encrypt(filePath!));
        }

        private async Task Encrypt(NormalizedPath filePath)
        {
            var context = new ProgressionContext();
            NavigationRequested?.Invoke(new NavigateToProgressRequest(context));
            await Encryption.Encrypt(SelectedProtocol, SelectedPreset.SizeInMB, filePath, context);
            
        }

        public void OnNavigatedTo(object? parameters)
        {
            this.filePath = (NormalizedPath)parameters!;   
        }


        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested;
    }

    internal record ChunkSizePreset(string Name, ushort SizeInMB);
}
