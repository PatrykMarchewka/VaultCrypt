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
using VaultCrypt.Exceptions;
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    internal class OpenVaultViewModel : INotifyPropertyChanged, INavigated, IViewModel, INavigatingViewModel
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


        internal OpenVaultViewModel()
        {
            EncryptedFilesCollectionView = CollectionViewSource.GetDefaultView(VaultSession.CurrentSession.ENCRYPTED_FILES);
            GoBackCommand = new RelayCommand(_ => GoBack());
            AddNewFileCommand = new RelayCommand(_ => AddNewFile());
            DecryptFileCommand = new RelayCommand(async _ => await DecryptFile(), _ => SelectedFile != null);
            DeleteFileCommand = new RelayCommand(async _ => await DeleteFile(), _ => SelectedFile != null);
            TrimCommand = new RelayCommand(async _ => await Trim());

            VaultSession.EncryptedFilesListUpdated += () => EncryptedFilesCollectionView.Refresh();
        }

        private void CreateSession()
        {
            try
            {
                byte[] password = null!;
                try
                {
                    password = PasswordHelper.SecureStringToBytes(this.password!);
                    this.password!.Clear();
                    VaultSession.CreateSessionFromFile(password, vaultPath!);
                }
                finally
                {
                    if (password is not null) CryptographicOperations.ZeroMemory(password);
                }
                this.VaultName = Path.GetFileName(vaultPath!);
            }
            catch(Exception ex)
            {
                throw new VaultException("Failed to open vault", ex);
            }
        }

        private void GoBack()
        {
            Dispose();
            NavigationRequested?.Invoke(new NavigateToMainRequest());
        }

        private void AddNewFile()
        {
            var dialog = FileDialogHelper.OpenFile("Select file to encrypt", true);

            if (dialog != null)
            {
                NavigationRequested?.Invoke(new NavigateToEncryptFileRequest(NormalizedPath.From(dialog)));
            }
        }

        private async Task DecryptFile()
        {
            var file = FileDialogHelper.SaveFile(SelectedFile!.Value.Value);
            if (file != null)
            {
                try
                {
                    var context = new ProgressionContext();
                    NavigationRequested?.Invoke(new NavigateToProgressRequest(context));
                    await Decryption.Decrypt(SelectedFile!.Value.Key, NormalizedPath.From(file)!, context);
                }
                catch(OperationCanceledException ex)
                {
                    throw VaultException.OperationCancelledException(ex);
                }
                catch(Exception ex)
                {
                    throw new VaultException("Failed to decrypt selected file", ex);
                }
            }
        }

        private async Task DeleteFile()
        {
            try
            {
                var context = new ProgressionContext();
                NavigationRequested?.Invoke(new NavigateToProgressRequest(context));
                await Task.Run(() => FileHelper.DeleteFileFromVault(SelectedFile!.Value, context));
            }
            catch (OperationCanceledException ex)
            {
                throw VaultException.OperationCancelledException(ex);
            }
            catch (Exception ex)
            {
                throw new VaultException("Failed to delete selected file from vault", ex);
            }
        }

        private async Task Trim()
        {
            try
            {
                var context = new ProgressionContext();
                NavigationRequested?.Invoke(new NavigateToProgressRequest(context));
                await Task.Run(() => FileHelper.TrimVault(context));
            }
            catch (OperationCanceledException ex)
            {
                throw VaultException.OperationCancelledException(ex);
            }
            catch (Exception ex)
            {
                throw new VaultException("Failed to trim vault", ex);
            }
            
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
                vaultPath = (NormalizedPath)p.GetType().GetProperty("VaultPath")!.GetValue(p)!;
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
        public event Action<NavigationRequest> NavigationRequested;
    }
}
