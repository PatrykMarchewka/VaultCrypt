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
    public class CreateVaultViewModel : INotifyPropertyChanged, INavigatingViewModel
    {
        private readonly IFileDialogService _fileDialogService;
        private readonly IVaultService _vaultService;

        private string _vaultFolder = null!;
        public string VaultFolder
        {
            get => _vaultFolder;
            set
            {
                if (_vaultFolder == value) return;
                _vaultFolder = value;
                OnPropertyChanged(nameof(VaultFolder));
            }
        }
        private string _vaultName = null!;
        public string VaultName
        {
            get => _vaultName;
            set
            {
                if (_vaultName == value) return;
                _vaultName = value;
                OnPropertyChanged(nameof(VaultName));
            }
        }
        private ISecureBuffer? _passwordBuffer;



        public IReadOnlyList<IterationPreset> IterationPresets { get; } =
        [
            new(Name: "Fast", Iterations: 200_000),
            new(Name: "Balanced", Iterations: 500_000),
            new(Name: "Strong", Iterations: 1_000_000),
            new(Name: "Ultra Strong", Iterations: 1_500_000)
        ];

        private IterationPreset _selectedPreset = null!;
        public IterationPreset SelectedPreset
        {
            get => _selectedPreset;
            set
            {
                if (_selectedPreset == value) return;
                _selectedPreset = value;
                OnPropertyChanged(nameof(SelectedPreset));
            }
        }

        public ICommand GoBackCommand { get; }
        public ICommand SelectFolderCommand { get; }
        public ICommand CreateVaultCommand { get; }

        public CreateVaultViewModel(IFileDialogService fileDialogService, IVaultService vaultService)
        {
            ArgumentNullException.ThrowIfNull(fileDialogService);
            ArgumentNullException.ThrowIfNull(vaultService);

            this._fileDialogService = fileDialogService;
            this._vaultService = vaultService;
            SelectedPreset = IterationPresets[0];
            VaultFolder = AppContext.BaseDirectory;
            GoBackCommand = new RelayCommand(_ => NavigationRequested?.Invoke(new NavigateToMainRequest()));
            SelectFolderCommand = new RelayCommand(_ => SelectFolder());
            CreateVaultCommand = new RelayCommand(_ => CreateVault());
        }

        public void SelectFolder()
        {
            string? path = _fileDialogService.OpenFolder("Select folder");

            if (path != null)
            {
                VaultFolder = path;
            }
        }

        public void CreateVault()
        {
            ValidationHelper.NotEmptyString(VaultFolder, "Vault folder");
            ValidationHelper.NotEmptyString(VaultName, "Vault name");
            ValidationHelper.NotEmptySecureBuffer(_passwordBuffer, "Vault password");

            NormalizedPath folderPath = NormalizedPath.From(VaultFolder);
            NormalizedPath vaultPath = NormalizedPath.From($"{folderPath}\\{VaultName}.vlt");

            _vaultService.CreateVault(folderPath, VaultName, _passwordBuffer!.AsSpan, SelectedPreset.Iterations);
            NavigationRequested?.Invoke(new NavigateToPasswordInputRequest(vaultPath));
        }

        /// <summary>
        /// Disposes previous password buffer and creates new one from provided <paramref name="password"/>
        /// </summary>
        /// <param name="password">Password to use</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="password"/> is set to null</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is set to empty or whitespace only characters</exception>
        public void RecievePasswordString(string password)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(password);

            _passwordBuffer?.Dispose();
            _passwordBuffer = SecureBuffer.StringToSecureBuffer(password);
        }


        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }

    public record IterationPreset(string Name, int Iterations);
}
