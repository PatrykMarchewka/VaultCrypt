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

        private static readonly (int position, string name, int iterations)[] IterationPresets =
        {
            (0, "Fast", 200_000),
            (1, "Balanced", 500_000),
            (2, "Strong", 1_000_000),
            (3, "Ultra Strong", 1_500_000)
        };

        public static IEnumerable<object[]> IterationPresetValues => IterationPresets.Select(preset => new object[] { preset.position, preset.name, preset.iterations });

        [Fact]
        internal void IterationPresetsHasCorrectAmountOfItems()
        {
            Assert.Equal(IterationPresets.Length, _viewModel.IterationPresets.Count);
        }

        [Theory]
        [MemberData(nameof(IterationPresetValues))]
        internal void IterationPresetsInitializedCorrectly(int position, string name, int iterations)
        {
            Assert.Equal(name, _viewModel.IterationPresets[position].Name);
            Assert.Equal(iterations, _viewModel.IterationPresets[position].Iterations);
        }

        [Theory]
        [MemberData(nameof(IterationPresetValues))]
        internal void IterationPresetsHaveUniqueValues(int _, string name, int iterations)
        {
            Assert.Single(_viewModel.IterationPresets.Where(preset => preset.Name == name));
            Assert.Single(_viewModel.IterationPresets.Where(preset => preset.Iterations == iterations));
        }

        [Fact]
        internal void IterationPresetsIncreaseInIterations()
        {
            for (int i = 1; i < IterationPresets.Length; i++)
            {
                Assert.True(_viewModel.IterationPresets[i].Iterations > _viewModel.IterationPresets[i - 1].Iterations);
            }
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

        private static SecureString NotEmptySecureString()
        {
            SecureString secureString = new();
            secureString.AppendChar('a');
            return secureString;
        }

        public static TheoryData<string?, string?, SecureString?> InvalidCreateVaultParameters = new TheoryData<string?, string?, SecureString?>()
        {
            {string.Empty, "Name", NotEmptySecureString() },
            {"  ", "Name", NotEmptySecureString()},
            {null, "Name", NotEmptySecureString() },
            {"Folder", string.Empty, NotEmptySecureString() },
            {"Folder", "    ", NotEmptySecureString() },
            {"Folder", null, NotEmptySecureString() },
            {"Folder", "Name", null },
            {"Folder", "Name", new SecureString() }
        };

        [Theory]
        [MemberData(nameof(InvalidCreateVaultParameters))]
        internal void CreateVaultThrowsForInvalidParameters(string folder, string name, SecureString password)
        {
            _viewModel.VaultFolder = folder;
            _viewModel.VaultName = name;
            _viewModel.Password = password;

            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => _viewModel.CreateVault());
        }

        [Fact]
        internal void NavigationRequestedRaised()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.GoBackCommand.Execute(null);
            Assert.Equal(1, eventRaisedCount);
        }
    }
}
