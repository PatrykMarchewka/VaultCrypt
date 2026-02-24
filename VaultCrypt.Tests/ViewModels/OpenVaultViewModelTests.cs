using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;
using VaultCrypt.Tests.Services;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Tests.ViewModels
{
    public class OpenVaultViewModelTests
    {
        private VaultCrypt.ViewModels.OpenVaultViewModel _viewModel;
        private readonly FakeFileDialogService fakeFileDialogService = new();
        private readonly FakeVaultService fakeVaultService = new();
        private readonly FakeDecryptionService fakeDecryptionService = new();
        private readonly FakeVaultSession fakeVaultSession = FakeVaultSession.EmptyMockSession();

        public OpenVaultViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.OpenVaultViewModel(fakeFileDialogService, fakeVaultService, fakeDecryptionService, fakeVaultSession);
        }

        private void CreateVMWithFileDialogService(string? returnValue)
        {
            var fileDialogService = new FakeFileDialogService() { ReturnValue = returnValue };
            this._viewModel = new VaultCrypt.ViewModels.OpenVaultViewModel(fileDialogService, fakeVaultService, fakeDecryptionService, fakeVaultSession);
        }

        [Fact]
        void FilteredTextRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.FilteredText = "new";

            Assert.Equal(nameof(_viewModel.FilteredText), changedProperty);
        }

        [Fact]
        void FilteredTextDoesNotRaisePropertyChanged()
        {
            string text = "text";
            _viewModel.FilteredText = text;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.FilteredText = text;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void FilteredTextChangesValues()
        {
            string expected = "changed";
            _viewModel.FilteredText = expected;

            Assert.Equal(expected, _viewModel.FilteredText);
        }

        [Fact]
        void FilteredTextCallsFilterMethod_ReturnsEmpty()
        {
            //Asserts that changing FilteredText calls Filter method by ensuring that the filtered text matches no hits  
            Assert.False(_viewModel.EncryptedFilesCollectionView.IsEmpty);
            string text = "IMPOSSIBLEITEMTHATWILLNEVERAPPEARINTESTS";
            _viewModel.FilteredText = text;

            Assert.True(_viewModel.EncryptedFilesCollectionView.IsEmpty);
        }

        [Fact]
        void FilteredTextCallsFilterMethod_ReturnsFull()
        {
            //Asserts that changing FilteredText calls Filter method by ensuring that the filtered text matches every hit
            Assert.False(_viewModel.EncryptedFilesCollectionView.IsEmpty);
            string text = "";
            _viewModel.FilteredText = text;

            var filtered = fakeVaultSession.ENCRYPTED_FILES.Where(fileInfo => fileInfo.Value.FileName.Contains(text, StringComparison.OrdinalIgnoreCase));

            Assert.Equal(_viewModel.EncryptedFilesCollectionView.Cast<object>().Count(), filtered.Count());
        }

        [Fact]
        void FilteredTextCallsFilterMethod_ReturnsSingle()
        {
            //Asserts that changing FilteredText calls Filter method by ensuring that the filtered text matches single hit
            Assert.False(_viewModel.EncryptedFilesCollectionView.IsEmpty);
            string text = "TEST";
            _viewModel.FilteredText = text;

            var filtered = fakeVaultSession.ENCRYPTED_FILES.Where(fileInfo => fileInfo.Value.FileName.Contains(text, StringComparison.OrdinalIgnoreCase));

            Assert.Equal(_viewModel.EncryptedFilesCollectionView.Cast<object>().Count(), filtered.Count());
        }


        [Fact]
        void SelectedFileRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo("SelectedFileRaisesPropertyChanged test", 0));

            Assert.Equal(nameof(_viewModel.SelectedFile), changedProperty);
        }

        [Fact]
        void SelectedFileDoesNotRaisePropertyChanged()
        {
            _viewModel.SelectedFile = null;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedFile = null;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void SelectedFileChangesValue()
        {
            var kvp = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo("SelectedFileChangesValue test", 0));
            _viewModel.SelectedFile = kvp;

            Assert.Equal(kvp, _viewModel.SelectedFile);
        }

        [Fact]
        void SelectedFileDecryptCommandCanExecuteChanges()
        {
            int eventRaisedCount = 0;
            (_viewModel.DecryptFileCommand as RelayCommand)!.CanExecuteChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(1, new EncryptedFileInfo("SelectedFileDecryptCommandCanExecuteChanges test", 0));
            Assert.Equal(1, eventRaisedCount);
            Assert.True(_viewModel.DecryptFileCommand.CanExecute(null));

            _viewModel.SelectedFile = null;
            Assert.Equal(2, eventRaisedCount);
            Assert.False(_viewModel.DecryptFileCommand.CanExecute(null));
        }

        [Fact]
        void SelectedFileDeleteCommandCanExecuteChanges()
        {
            int eventRaisedCount = 0;
            (_viewModel.DeleteFileCommand as RelayCommand)!.CanExecuteChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(2, new EncryptedFileInfo("SelectedFileDeleteCommandCanExecuteChanges test", 0));
            Assert.Equal(1, eventRaisedCount);
            Assert.True(_viewModel.DeleteFileCommand.CanExecute(null));

            _viewModel.SelectedFile = null;
            Assert.Equal(2, eventRaisedCount);
            Assert.False(_viewModel.DeleteFileCommand.CanExecute(null));
        }

        [Fact]
        void CreateSessionCallsMethod()
        {
            //Reflection in order to modify private field, replace with something better when possible
            //CreateSession calls PasswordHelper.SecureStringToBytes() on password
            //TODO: Use something less brittle than reflection
            SecureString newPassword = new SecureString();
            newPassword.AppendChar('c');
            var reflection = typeof(OpenVaultViewModel).GetField("password", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            reflection!.SetValue(_viewModel, newPassword);
            _viewModel.CreateSession();
            Assert.True(fakeVaultService.CreateSessionFromFileWasCalled);
        }

        [Fact]
        void AddNewFileRaisesNavigationRequest()
        {
            CreateVMWithFileDialogService("return");
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.AddNewFile();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        void AddNewFileDoesNotRaiseNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.AddNewFile();
            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        async void DecryptFileRaisesNavigationRequest()
        {
            CreateVMWithFileDialogService("return");
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo(null, 0, null));

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.DecryptFile();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        async void DecryptFileDoesNotRaiseNavigationRequest()
        {
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo(null, 0, null));

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.DecryptFile();
            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        async void DeleteFileRaisesNavigationRequest()
        {
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo(null, 0, null));

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.DeleteFile();
        }

        [Fact]
        async void DeleteFileCallsMethod()
        {
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo(null, 0, null));

            await _viewModel.DeleteFile();
            Assert.True(fakeVaultService.DeleteFileFromVaultWasCalled);
        }

        [Fact]
        async void TrimRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.Trim();
        }

        [Fact]
        async void TrimCallsMethod()
        {
            await _viewModel.Trim();
            Assert.True(fakeVaultService.TrimVaultWasCalled);
        }

        [Fact]
        void NavigationRequestedRaised()
        {
            //Reflection in order to modify private field, replace with something better when possible
            //GoBack command calls Dispose which calls .Clear() on password
            //TODO: Use something less brittle than reflection
            SecureString newPassword = new SecureString();
            newPassword.AppendChar('c');
            var reflection = typeof(OpenVaultViewModel).GetField("password", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            reflection!.SetValue(_viewModel, newPassword);

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.GoBackCommand.Execute(null);

            Assert.Equal(1, eventRaisedCount);
        }
    }
}
