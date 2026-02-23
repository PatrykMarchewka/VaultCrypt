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
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    public class OpenVaultViewModel : INotifyPropertyChanged, INavigated, IViewModel, INavigatingViewModel
    {
        private readonly IFileDialogService _fileDialogService;
        private readonly IVaultService _vaultService;
        private readonly IDecryptionService _decryptionService;
        private readonly IVaultSession _session;

        private SecureString? password;
        private NormalizedPath? vaultPath;
        public ICollectionView EncryptedFilesCollectionView { get; private set; } = null!;


        public string VaultName { get; private set; } = null!;

        private string _filteredText = null!;
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

        private KeyValuePair<long, EncryptedFileInfo>? _selectedFile;
        public KeyValuePair<long, EncryptedFileInfo>? SelectedFile
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


        public OpenVaultViewModel(IFileDialogService fileDialogService, IVaultService vaultService, IDecryptionService decryptionService, IVaultSession session)
        {
            this._fileDialogService = fileDialogService;
            this._vaultService = vaultService;
            this._decryptionService = decryptionService;
            this._session = session;
            EncryptedFilesCollectionView = CollectionViewSource.GetDefaultView(_session.ENCRYPTED_FILES);
            GoBackCommand = new RelayCommand(_ => GoBack());
            AddNewFileCommand = new RelayCommand(_ => AddNewFile());
            DecryptFileCommand = new RelayCommand(async _ => await DecryptFile(), _ => SelectedFile != null);
            DeleteFileCommand = new RelayCommand(async _ => await DeleteFile(), _ => SelectedFile != null);
            TrimCommand = new RelayCommand(async _ => await Trim());

            _session.EncryptedFilesListUpdated += () => EncryptedFilesCollectionView.Refresh();
        }

        public void CreateSession()
        {
            byte[] password = null!;
            try
            {
                password = PasswordHelper.SecureStringToBytes(this.password!);
                this.password!.Clear();
                _vaultService.CreateSessionFromFile(password, vaultPath!);
            }
            finally
            {
                if (password is not null) CryptographicOperations.ZeroMemory(password);
            }
            this.VaultName = Path.GetFileName(vaultPath!);
        }

        public void RefreshCollection()
        {
            using var vaultFS = new FileStream(_session.VAULTPATH!, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            _vaultService.RefreshEncryptedFilesList(vaultFS);
        }

        public void GoBack()
        {
            Dispose();
            NavigationRequested?.Invoke(new NavigateToMainRequest());
        }

        public void AddNewFile()
        {
            var dialog = _fileDialogService.OpenFile("Select file to encrypt", true);

            if (dialog != null)
            {
                NavigationRequested?.Invoke(new NavigateToEncryptFileRequest(NormalizedPath.From(dialog)!));
            }
        }

        public async Task DecryptFile()
        {
            var file = _fileDialogService.SaveFile(SelectedFile!.Value.Value.FileName);
            if (file != null)
            {
                var context = new ProgressionContext();
                NavigationRequested?.Invoke(new NavigateToProgressRequest(context));
                await _decryptionService.Decrypt(SelectedFile!.Value.Key, NormalizedPath.From(file)!, context);
            }
        }

        public async Task DeleteFile()
        {
            var context = new ProgressionContext();
            NavigationRequested?.Invoke(new NavigateToProgressRequest(context));
            await Task.Run(() => _vaultService.DeleteFileFromVault(SelectedFile!.Value, context));
        }

        public async Task Trim()
        {
            var context = new ProgressionContext();
            NavigationRequested?.Invoke(new NavigateToProgressRequest(context));
            await Task.Run(() => _vaultService.TrimVault(context));
        }

        public void Filter(string text)
        {
            EncryptedFilesCollectionView.Filter = file => { var kvp = (KeyValuePair<long, EncryptedFileInfo>)file; return kvp.Value.FileName.Contains(text, StringComparison.OrdinalIgnoreCase); };
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

        public void Dispose()
        {
            this.password!.Clear();
            this.vaultPath = null;
            this.SelectedFile = null;
        }

        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
