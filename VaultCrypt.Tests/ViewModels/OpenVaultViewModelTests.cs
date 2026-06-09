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
        private readonly FakeVaultSession fakeVaultSession = FakeVaultSession.EmptyMockSession;

        public OpenVaultViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.OpenVaultViewModel(fakeFileDialogService, fakeVaultService, fakeDecryptionService, fakeVaultSession);
        }

        private void CreateVMWithFileDialogService(string? returnValue)
        {
            var fileDialogService = new FakeFileDialogService() { ReturnValue = returnValue };
            this._viewModel = new VaultCrypt.ViewModels.OpenVaultViewModel(fileDialogService, fakeVaultService, fakeDecryptionService, fakeVaultSession);
        }

        private (ISecureBuffer password, NormalizedPath vaultPath) GetViewModelValues()
        {
            //Reflection in order to read private field, replace with something better when possible
            //TODO: Use something less brittle than reflection
            ISecureBuffer password = (ISecureBuffer)_viewModel.GetType().GetField("_passwordBuffer", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(_viewModel)!;
            NormalizedPath vaultPath = (NormalizedPath)_viewModel.GetType().GetField("_vaultPath", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(_viewModel)!;

            return (password, vaultPath);
        }



        private void SetViewModelValues(ISecureBuffer? buffer = null, string newVaultPath = "NewVaultPath")
        {
            //Reflection in order to modify private field, replace with something better when possible
            //TODO: Use something less brittle than reflection
            buffer ??= new SecureBuffer.SecureKeyBuffer(1);
            var reflectionPassword = typeof(VaultCrypt.ViewModels.OpenVaultViewModel).GetField("_passwordBuffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            reflectionPassword!.SetValue(_viewModel, buffer);
            var reflectionVaultPath = typeof(VaultCrypt.ViewModels.OpenVaultViewModel).GetField("_vaultPath", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            reflectionVaultPath!.SetValue(_viewModel, NormalizedPath.From(newVaultPath));
        }


        [Fact]
        internal void FilteredTextRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.FilteredText = "new";

            Assert.Equal(nameof(_viewModel.FilteredText), changedProperty);
        }

        [Fact]
        internal void FilteredTextDoesNotRaisePropertyChanged()
        {
            string text = "text";
            _viewModel.FilteredText = text;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.FilteredText = text;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void FilteredTextChangesValues()
        {
            string expected = "changed";
            _viewModel.FilteredText = expected;

            Assert.Equal(expected, _viewModel.FilteredText);
        }

        [Fact]
        internal void FilteredTextCallsFilterMethod_ReturnsEmpty()
        {
            _viewModel.EncryptedFilesCollectionView.Filter = null;
            //Asserts that changing FilteredText calls Filter method by ensuring that the filtered text matches no hits  
            Assert.False(_viewModel.EncryptedFilesCollectionView.IsEmpty);
            string text = "IMPOSSIBLEITEMTHATWILLNEVERAPPEARINTESTS";
            _viewModel.FilteredText = text;

            Assert.True(_viewModel.EncryptedFilesCollectionView.IsEmpty);
        }

        [Fact]
        internal void FilteredTextCallsFilterMethod_ReturnsFull()
        {
            _viewModel.EncryptedFilesCollectionView.Filter = null;
            //Asserts that changing FilteredText calls Filter method by ensuring that the filtered text matches every hit
            Assert.False(_viewModel.EncryptedFilesCollectionView.IsEmpty);
            string text = "";
            _viewModel.FilteredText = text;

            var filtered = fakeVaultSession.ENCRYPTED_FILES.Where(fileInfo => fileInfo.Value.FileName.Contains(text, StringComparison.OrdinalIgnoreCase));

            Assert.Equal(_viewModel.EncryptedFilesCollectionView.Cast<object>().Count(), filtered.Count());
        }

        [Fact]
        internal void FilteredTextCallsFilterMethod_ReturnsSingle()
        {
            _viewModel.EncryptedFilesCollectionView.Filter = null;
            //Asserts that changing FilteredText calls Filter method by ensuring that the filtered text matches single hit
            Assert.False(_viewModel.EncryptedFilesCollectionView.IsEmpty);
            string text = "TEST";
            _viewModel.FilteredText = text;

            var filtered = fakeVaultSession.ENCRYPTED_FILES.Where(fileInfo => fileInfo.Value.FileName.Contains(text, StringComparison.OrdinalIgnoreCase));

            Assert.Equal(_viewModel.EncryptedFilesCollectionView.Cast<object>().Count(), filtered.Count());
        }


        [Fact]
        internal void SelectedFileRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo("SelectedFileRaisesPropertyChanged test", 0));

            Assert.Equal(nameof(_viewModel.SelectedFile), changedProperty);
        }

        [Fact]
        internal void SelectedFileDoesNotRaisePropertyChanged()
        {
            _viewModel.SelectedFile = null;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedFile = null;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void SelectedFileChangesValue()
        {
            var kvp = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo("SelectedFileChangesValue test", 0));
            _viewModel.SelectedFile = kvp;

            Assert.Equal(kvp, _viewModel.SelectedFile);
        }

        [Fact]
        internal void SelectedFileDecryptCommandCanExecuteChanges()
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
        internal void SelectedFileDeleteCommandCanExecuteChanges()
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
        internal void CreateSessionCallsMethod()
        {
            SetViewModelValues();
            _viewModel.CreateSession();
            Assert.True(fakeVaultService.CreateSessionFromFileWasCalled);
        }

        [Fact]
        internal void CreateSessionSetsVaultName()
        {
            string vaultPath = "CreateSessionSetsVaultPathTest";
            SetViewModelValues(newVaultPath: vaultPath);
            _viewModel.CreateSession();
            Assert.Equal(vaultPath, _viewModel.VaultName);
        }

        [Fact]
        internal void RefreshCollectionCallsMethod()
        {
            //RefreshCollection opens FileStream to _session.VAULTPATH
            var vaultFilePath = TestsHelper.CreateTemporaryFile(0);
            fakeVaultSession.VAULTPATH = vaultFilePath;
            try
            {
                _viewModel.RefreshCollection();
                Assert.True(fakeVaultService.RefreshEncryptedFilesListWasCalled);
            }
            finally
            {
                File.Delete(vaultFilePath);
            }
        }

        [Fact]
        internal void GoBackDisposesClass()
        {
            SetViewModelValues();

            _viewModel.GoBack();
            (ISecureBuffer, NormalizedPath) actualValues = GetViewModelValues();
            Assert.Throws<ObjectDisposedException>(() => actualValues.Item1.Length);
            Assert.Null(actualValues.Item2);
            Assert.Null(_viewModel.SelectedFile);
        }

        [Fact]
        internal void GoBackRaisesNavigationRequest()
        {
            SetViewModelValues();

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.GoBack();

            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        internal void AddNewFileRaisesNavigationRequest()
        {
            CreateVMWithFileDialogService("return");
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.AddNewFile();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        internal void AddNewFileDoesNotRaiseNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.AddNewFile();
            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal async void DecryptFileRaisesNavigationRequest()
        {
            CreateVMWithFileDialogService("return");
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo(null, 0, null));

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.DecryptFile();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        internal async void DecryptFileDoesNotRaiseNavigationRequest()
        {
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo(null, 0, null));

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.DecryptFile();
            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal async void DeleteFileRaisesNavigationRequest()
        {
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo(null, 0, null));

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.DeleteFile();
        }

        [Fact]
        internal async void DeleteFileCallsMethod()
        {
            _viewModel.SelectedFile = new KeyValuePair<long, EncryptedFileInfo>(0, new EncryptedFileInfo(null, 0, null));

            await _viewModel.DeleteFile();
            Assert.True(fakeVaultService.DeleteFileFromVaultWasCalled);
        }

        [Fact]
        internal async void TrimRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.Trim();
        }

        [Fact]
        internal async void TrimCallsMethod()
        {
            await _viewModel.Trim();
            Assert.True(fakeVaultService.TrimVaultWasCalled);
        }

        [Fact]
        internal void OnNavigatedToSetsValues()
        {
            NormalizedPath expectedPath = NormalizedPath.From("OnNavigatedToSetsValuesTest");
            SecureBuffer.SecureKeyBuffer expectedBuffer = new SecureBuffer.SecureKeyBuffer(1);
            try
            {
                (ISecureBuffer, NormalizedPath) expected = (expectedBuffer, expectedPath);

                _viewModel.OnNavigatedTo(expected);
                (ISecureBuffer password, NormalizedPath vaultPath) actual = GetViewModelValues();

                Assert.Equal(expectedPath, actual.vaultPath);
                Assert.True(expectedBuffer.AsSpan.SequenceEqual(actual.password.AsSpan));
            }
            finally
            {
                expectedBuffer.Dispose();
            }
        }

        [Fact]
        internal void OnNavigatedToCallsCreateSession()
        {
            NormalizedPath expectedPath = NormalizedPath.From("OnNavigatedToCallsCreateSessionTest");
            (ISecureBuffer, NormalizedPath) expected = (new FakeSecureBuffer(empty: false), expectedPath);
            _viewModel.OnNavigatedTo(expected);

            //Because viewmodel is not spoofed there is no clear way to prove that CreateSession was called so we're asserting that CreateSession changed _viewmodel.VaultName
            Assert.Equal(expectedPath, _viewModel.VaultName);
        }

        public static TheoryData<object?, Type> InvalidParameters = new TheoryData<object?, Type>()
        {
            {null,  typeof(ArgumentNullException)},
            {new(), typeof(ArgumentException) },
            {((ISecureBuffer?)null, NormalizedPath.From("OK")), typeof(ArgumentException) },
            {((ISecureBuffer)new FakeSecureBuffer(empty: true), NormalizedPath.From("OK")), typeof(ArgumentException) },
            {((ISecureBuffer)new FakeSecureBuffer(empty: false), (NormalizedPath?)null), typeof(ArgumentException) },
            {((ISecureBuffer)new FakeSecureBuffer(empty: false), NormalizedPath.From("")), typeof(ArgumentException) },
            {((ISecureBuffer)new FakeSecureBuffer(empty: false), NormalizedPath.From("   ")), typeof(ArgumentException) }
        };

        [Theory]
        [MemberData(nameof(InvalidParameters))]
        internal void OnNavigatedToThrowsForInvalidParameters(object? parameters, Type expectedException)
        {
            Assert.Throws(expectedException, () => _viewModel.OnNavigatedTo(parameters!));
        }
    }
}
