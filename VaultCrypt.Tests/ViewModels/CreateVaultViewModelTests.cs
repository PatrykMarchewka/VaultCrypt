using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Tests.Services;

namespace VaultCrypt.Tests.ViewModels
{
    public class CreateVaultViewModelTests
    {
        private VaultCrypt.ViewModels.CreateVaultViewModel _viewModel;
        private readonly FakeVaultService fakeVaultService = new();

        public CreateVaultViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.CreateVaultViewModel(new FakeFileDialogService(), fakeVaultService);
        }
        private void CreateVMWithDialogService(string? returnValue)
        {
            var fake = new FakeFileDialogService { ReturnValue = returnValue };
            this._viewModel = new VaultCrypt.ViewModels.CreateVaultViewModel(fake, fakeVaultService);
        }


        [Fact]
        void VaultFolderRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.VaultFolder = "C:\\RaisedProperty";

            Assert.Equal(nameof(_viewModel.VaultFolder), changedProperty);
        }

        [Fact]
        void VaultFolderDoesNotRaisePropertyChanged()
        {
            string value = "C:\\DoesntRaiseProperty";
            _viewModel.VaultFolder = value;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.VaultFolder = value;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void VaultFolderChangesValue()
        {
            string expected = "C:\\ChangedValue";
            _viewModel.VaultFolder = expected;

            Assert.Equal(expected, _viewModel.VaultFolder);
        }



        [Fact]
        void VaultNameRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.VaultName = "RaisesProperty";

            Assert.Equal(nameof(_viewModel.VaultName), changedProperty);
        }

        [Fact]
        void VaultNameDoesNotRaisePropertyChanged()
        {
            string value = "DoesntRaiseProperty";
            _viewModel.VaultName = value;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.VaultName = value;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void VaultNameChangesValue()
        {
            string expected = "ChangedValue";
            _viewModel.VaultName = expected;

            Assert.Equal(expected, _viewModel.VaultName);
        }

        [Fact]
        void PasswordRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            SecureString expected = new SecureString();
            expected.AppendChar('a');
            _viewModel.Password = expected;

            Assert.Equal(nameof(_viewModel.Password), changedProperty);
        }

        [Fact]
        void PasswordDoesNotRaisePropertyChanged()
        {
            SecureString value = new SecureString();
            _viewModel.Password = value;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.Password = value;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void IterationPresetsInitializedCorrectly()
        {
            Assert.Equal(4, _viewModel.IterationPresets.Count);

            Assert.Equal("Fast", _viewModel.IterationPresets[0].Name);
            Assert.Equal(200_000, _viewModel.IterationPresets[0].Iterations);

            Assert.Equal("Balanced", _viewModel.IterationPresets[1].Name);
            Assert.Equal(500_000, _viewModel.IterationPresets[1].Iterations);

            Assert.Equal("Strong", _viewModel.IterationPresets[2].Name);
            Assert.Equal(1_000_000, _viewModel.IterationPresets[2].Iterations);

            Assert.Equal("Ultra Strong", _viewModel.IterationPresets[3].Name);
            Assert.Equal(1_500_000, _viewModel.IterationPresets[3].Iterations);
        }

        [Theory]
        [InlineData(0,1)]
        [InlineData(1,2)]
        [InlineData(2,3)]
        void IterationPresetsIncreaseInIterations(int firstIndex, int secondIndex)
        {
            Assert.True(_viewModel.IterationPresets[firstIndex].Iterations < _viewModel.IterationPresets[secondIndex].Iterations);
        }

        [Fact]
        void SelectedPresetRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.SelectedPreset = _viewModel.IterationPresets[1];

            Assert.Equal(nameof(_viewModel.SelectedPreset), changedProperty);
        }

        [Fact]
        void SelectedPresetDoesNotRaisePropertyChanged()
        {
            _viewModel.SelectedPreset = _viewModel.IterationPresets[2];
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedPreset = _viewModel.IterationPresets[2];

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void SelectFolderSetsVaultFolder()
        {
            CreateVMWithDialogService("value");
            _viewModel.SelectFolder();

            Assert.Equal("value", _viewModel.VaultFolder);
        }

        [Fact]
        void SelectFolderDoesNotSetVaultFolder()
        {
            string expected = _viewModel.VaultFolder;
            CreateVMWithDialogService(null);
            _viewModel.SelectFolder();

            Assert.Equal(expected, _viewModel.VaultFolder);
        }

        [Fact]
        void CreateVaultCallsMethod()
        {
            _viewModel.VaultFolder = "folder";
            _viewModel.VaultName = "name";
            SecureString password = new SecureString();
            password.AppendChar('a');
            _viewModel.Password = password;

            _viewModel.CreateVault();
            Assert.True(fakeVaultService.CreateVaultWasCalled);
        }

        [Fact]
        void CreateVaultRaisesNavigationRequest()
        {
            _viewModel.VaultFolder = "folder";
            _viewModel.VaultName = "name";
            SecureString password = new SecureString();
            password.AppendChar('a');
            _viewModel.Password = password;

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.CreateVault();
            Assert.Equal(1, eventRaisedCount);

        }

        [Fact]
        void CreateVaultThrowsForEmptyStringFolder()
        {
            _viewModel.VaultFolder = "";
            _viewModel.VaultName = "name";
            SecureString password = new SecureString();
            password.AppendChar('a');
            _viewModel.Password = password;

            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => _viewModel.CreateVault());
        }

        [Fact]
        void CreateVaultThrowsForEmptyStringName()
        {
            _viewModel.VaultFolder = "folder";
            _viewModel.VaultName = "";
            SecureString password = new SecureString();
            password.AppendChar('a');
            _viewModel.Password = password;

            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => _viewModel.CreateVault());
        }

        [Fact]
        void CreateVaultThrowsForEmptyStringPassword()
        {
            _viewModel.VaultFolder = "folder";
            _viewModel.VaultName = "name";
            _viewModel.Password = new SecureString();

            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => _viewModel.CreateVault());
        }

        [Fact]
        void NavigationRequestedRaised()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.GoBackCommand.Execute(null);

            Assert.Equal(1, eventRaisedCount);
        }
    }
}
