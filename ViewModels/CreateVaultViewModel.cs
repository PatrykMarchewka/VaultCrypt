using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace VaultCrypt.ViewModels
{
    internal class CreateVaultViewModel : INotifyPropertyChanged, IViewModel, INavigatingViewModel
    {
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
        private SecureString _password = null!;
        public SecureString Password
        {
            get => _password;
            set
            {
                if (_password == value) return;
                _password = value;
                OnPropertyChanged(nameof(Password));
            }
        }



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

        internal CreateVaultViewModel()
        {
            SelectedPreset = IterationPresets[0];

            GoBackCommand = new RelayCommand(_ => NavigationRequested?.Invoke(new NavigateToMainRequest()));
            SelectFolderCommand = new RelayCommand(_ => SelectFolder());
            CreateVaultCommand = new RelayCommand(_ => CreateVault());
        }

        internal void SelectFolder()
        {
            string? path = FileDialogHelper.OpenFolder("Select folder");

            if (path != null)
            {
                VaultFolder = path;
            }
        }

        internal void CreateVault()
        {
            ValidationHelper.NotEmptyString(VaultFolder, "Vault folder");
            ValidationHelper.NotEmptyString(VaultName, "Vault name");
            ValidationHelper.NotEmptySecureString(Password, "Vault password");

            NormalizedPath folderPath = NormalizedPath.From(VaultFolder)!;
            NormalizedPath vaultPath = NormalizedPath.From($"{folderPath}\\{VaultName}.vlt")!;
            byte[]? passwordBytes = null;
            try
            {
                passwordBytes = PasswordHelper.SecureStringToBytes(Password);
                VaultSession.CreateVault(folderPath, VaultName, passwordBytes, SelectedPreset.Iterations);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
            NavigationRequested?.Invoke(new NavigateToPasswordInputRequest(vaultPath));
        }


        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }

    internal record IterationPreset(string Name, int Iterations);





}
