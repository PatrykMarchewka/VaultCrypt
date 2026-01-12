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
    internal class CreateVaultViewModel : INotifyPropertyChanged, IViewModel
    {
        private string _vaultFolder;
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
        private string _vaultName;
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
        private SecureString _password;
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

        private IterationPreset _selectedPreset;
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

        internal CreateVaultViewModel(INavigationService nav)
        {
            SelectedPreset = IterationPresets[0];

            GoBackCommand = new RelayCommand(_ => nav.NavigateToMain());
            SelectFolderCommand = new RelayCommand(_ => SelectFolder());
            CreateVaultCommand = new RelayCommand(_ => CreateVault(nav));
        }

        internal void SelectFolder()
        {
            string? path = FileDialogService.OpenFolder("Select folder");

            if (path != null)
            {
                VaultFolder = path;
            }
        }

        internal void CreateVault(INavigationService nav)
        {
            if (String.IsNullOrEmpty(VaultFolder))
            {
                throw new Exception("Folder path is null or empty");
                byte[] passwordBytes = PasswordHelper.SecureStringToBytes(Password);
            }
            if (String.IsNullOrEmpty(VaultName))
            {
                throw new Exception("Vault name is null or empty");
            }
            if (Password.Length == 0)
            {
                throw new Exception("Password is empty");
            }

            NormalizedPath folderPath = NormalizedPath.From(VaultFolder);
            FileHelper.WriteSmallFile(folderPath);


            FileHelper.CreateVault(folderPath, VaultName, passwordBytes, SelectedPreset.Iterations);
            CryptographicOperations.ZeroMemory(passwordBytes);

            nav.NavigateToPasswordInput(folderPath + "\\" + VaultName + ".vlt");
        }


        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
    }

    internal record IterationPreset(string Name, int Iterations);





}
