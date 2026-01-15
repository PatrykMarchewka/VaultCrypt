using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;
using System.Windows.Input;

namespace VaultCrypt.ViewModels
{
    internal class OpenVaultViewModel : INotifyPropertyChanged, INavigated, IViewModel
    {

        private SecureString? password;
        private NormalizedPath? vaultPath;
        public static ICollectionView EncryptedFilesCollectionView { get; private set; }


        public string VaultName { get; private set; }

        private string _filteredText;
        public string FilteredText
        {
            get => _filteredText;
            set
            {
                if (_filteredText == value) return;
                _filteredText = value;
                OnPropertyChanged(nameof(FilteredText));
                Filter(value);
            }
        }

        private KeyValuePair<long, string>? _selectedFile;
        public KeyValuePair<long, string>? SelectedFile
        {
            get => _selectedFile;
            set
            {
                if (_selectedFile.Equals(value)) return;
                _selectedFile = value;
                OnPropertyChanged(nameof(SelectedFile));

                (DecryptFileCommand as RelayCommand)!.RaiseCanExecuteChanged();
                (DeleteFileCommand as RelayCommand)!.RaiseCanExecuteChanged();
            }
        }

        public ICommand GoBackCommand { get; }
        public ICommand AddNewFileCommand { get; }
        public ICommand DecryptFileCommand { get; }
        public ICommand DeleteFileCommand { get; }
        public ICommand TrimCommand { get; }


        internal OpenVaultViewModel(INavigationService nav)
        {
            EncryptedFilesCollectionView = CollectionViewSource.GetDefaultView(VaultSession.ENCRYPTED_FILES);
            GoBackCommand = new RelayCommand(_ => GoBack(nav));
            AddNewFileCommand = new RelayCommand(_ => AddNewFile(nav));
            DecryptFileCommand = new RelayCommand(_ => DecryptFile(nav), _ => SelectedFile != null);
            DeleteFileCommand = new RelayCommand(_ => DeleteFile(nav), _ => SelectedFile != null);
            TrimCommand = new RelayCommand(_ => Trim(nav));
        }

        private void CreateSession()
        {
            byte[] password = PasswordHelper.SecureStringToBytes(this.password!);
            this.password!.Clear();
            VaultSession.CreateSession(password, vaultPath!);
            this.VaultName = Path.GetFileName(vaultPath!);
            CryptographicOperations.ZeroMemory(password);
        }

        private void GoBack(INavigationService nav)
        {
            Dispose();
            nav.NavigateToMain();
        }

        private void AddNewFile(INavigationService nav)
        {
            var dialog = FileDialogService.OpenFile("Select file to encrypt", true);

            if (dialog != null)
            {
                nav.NavigateToEncryptFile(NormalizedPath.From(dialog));
            }
        }

        private async Task DecryptFile(INavigationService nav)
        {
            var folder = FileDialogService.OpenFolder("Select folder to save file");
            if (folder != null)
            {
                var context = new VaultHelper.ProgressionContext();
                nav.NavigateToProgress(context);
                await Decryption.Decrypt(SelectedFile!.Value.Key, NormalizedPath.From(folder), context);
            }
        }

        private async Task DeleteFile(INavigationService nav)
        {
            var context = new VaultHelper.ProgressionContext();
            nav.NavigateToProgress(context);
            await Task.Run(() => FileHelper.DeleteFileFromVault(SelectedFile!.Value, context));
        }

        private async Task Trim(INavigationService nav)
        {
            var context = new VaultHelper.ProgressionContext();
            nav.NavigateToProgress(context);
            await Task.Run(() => FileHelper.TrimVault(context));
        }

        private void Filter(string text)
        {
            EncryptedFilesCollectionView.Filter = file => { var kvp = (KeyValuePair<long, string>)file; return kvp.Value.Contains(text, StringComparison.OrdinalIgnoreCase); };
            EncryptedFilesCollectionView.Refresh();
        }

        public void OnNavigatedTo(object? parameters)
        {
            if (parameters is { } p)
            {
                password = (SecureString)p.GetType().GetProperty("Password")!.GetValue(p)!;
                vaultPath = NormalizedPath.From((string)p.GetType().GetProperty("VaultPath")!.GetValue(p)!);
            }
            CreateSession();
        }

        private void Dispose()
        {
            this.password!.Clear();
            this.vaultPath = null;
            this.SelectedFile = null;
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
    }
}
