using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;
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

        private ISecureBuffer SetPasswordBuffer(ISecureBuffer buffer)
        {
            _viewModel.GetType().GetField("_passwordBuffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.SetValue(_viewModel, buffer);
            return buffer;
        }

        private ISecureBuffer SetPasswordBuffer()
        {
            ISecureBuffer keyBuffer = SecureBuffer.Create(1);
            return SetPasswordBuffer(keyBuffer);
        }


        public static TheoryData<IFileDialogService, IVaultService> InvalidParameters = new TheoryData<IFileDialogService, IVaultService>()
        {
            {null!, new FakeVaultService() },
            {new FakeFileDialogService(), null! }
        };

        [Theory]
        [MemberData(nameof(InvalidParameters))]
        internal void ConstructorThrowsForInvalidParameters(IFileDialogService fileDialogService, IVaultService vaultService)
        {
            Assert.Throws<ArgumentNullException>(() => new VaultCrypt.ViewModels.CreateVaultViewModel(fileDialogService, vaultService));
        }

        [Fact]
        internal void VaultFolderRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.VaultFolder = "C:\\RaisedProperty";

            Assert.Equal(nameof(_viewModel.VaultFolder), changedProperty);
        }

        [Fact]
        internal void VaultFolderDoesNotRaisePropertyChanged()
        {
            string value = "C:\\DoesntRaiseProperty";
            _viewModel.VaultFolder = value;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.VaultFolder = value;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void VaultFolderChangesValue()
        {
            string expected = "C:\\ChangedValue";
            _viewModel.VaultFolder = expected;

            Assert.Equal(expected, _viewModel.VaultFolder);
        }

        [Fact]
        internal void VaultNameRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.VaultName = "RaisesProperty";

            Assert.Equal(nameof(_viewModel.VaultName), changedProperty);
        }

        [Fact]
        internal void VaultNameDoesNotRaisePropertyChanged()
        {
            string value = "DoesntRaiseProperty";
            _viewModel.VaultName = value;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.VaultName = value;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void VaultNameChangesValue()
        {
            string expected = "ChangedValue";
            _viewModel.VaultName = expected;

            Assert.Equal(expected, _viewModel.VaultName);
        }

        private static readonly (int position, string name, int iterations)[] IterationPresets =
        {
            (0, "Fast", 200_000),
            (1, "Balanced", 500_000),
            (2, "Strong", 1_000_000),
            (3, "Ultra Strong", 1_500_000)
        };

        public static TheoryData<int, string, int> IterationPresetValues
        {
            get
            {
                var data = new TheoryData<int, string, int>();
                foreach (var item in IterationPresets)
                {
                    data.Add(item.position, item.name, item.iterations);
                }
                return data;
            }
        }

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
        internal void SelectedPresetRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.SelectedPreset = _viewModel.IterationPresets[1];

            Assert.Equal(nameof(_viewModel.SelectedPreset), changedProperty);
        }

        [Fact]
        internal void SelectedPresetDoesNotRaisePropertyChanged()
        {
            _viewModel.SelectedPreset = _viewModel.IterationPresets[2];
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedPreset = _viewModel.IterationPresets[2];

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void SelectFolderSetsVaultFolder()
        {
            CreateVMWithDialogService("value");
            _viewModel.SelectFolder();

            Assert.Equal("value", _viewModel.VaultFolder);
        }

        [Fact]
        internal void SelectFolderDoesNotSetVaultFolder()
        {
            string expected = _viewModel.VaultFolder;
            CreateVMWithDialogService(null);
            _viewModel.SelectFolder();

            Assert.Equal(expected, _viewModel.VaultFolder);
        }

        [Fact]
        internal void CreateVaultCallsMethod()
        {
            _viewModel.VaultFolder = "folder";
            _viewModel.VaultName = "name";
            ISecureBuffer password = null!;
            try
            {
                password = SetPasswordBuffer();
                _viewModel.CreateVault();
                Assert.True(fakeVaultService.CreateVaultWasCalled);
            }
            finally
            {
                password.Dispose();
            }
        }

        [Fact]
        internal void CreateVaultRaisesNavigationRequest()
        {
            _viewModel.VaultFolder = "folder";
            _viewModel.VaultName = "name";
            ISecureBuffer password = null!;
            try
            {
                password = SetPasswordBuffer();

                int eventRaisedCount = 0;
                _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
                _viewModel.CreateVault();
                Assert.Equal(1, eventRaisedCount);
            }
            finally
            {
                password.Dispose();
            }

        }

        public static TheoryData<string?, string?, FakeSecureBuffer?> InvalidCreateVaultParameters = new TheoryData<string?, string?, FakeSecureBuffer?>()
        {
            {string.Empty, "Name", new FakeSecureBuffer(empty: false)},
            {"  ", "Name", new FakeSecureBuffer(empty: false)},
            {null, "Name", new FakeSecureBuffer(empty: false)},
            {"Folder", string.Empty, new FakeSecureBuffer(empty: false)},
            {"Folder", "    ", new FakeSecureBuffer(empty: false)},
            {"Folder", null, new FakeSecureBuffer(empty: false)},
            {"Folder", "Name", new FakeSecureBuffer(empty: true)},
            {"Folder", "Name", null}
        };

        [Theory]
        [MemberData(nameof(InvalidCreateVaultParameters))]
        internal void CreateVaultThrowsForInvalidParameters(string folder, string name, FakeSecureBuffer secureBuffer)
        {
            _viewModel.VaultFolder = folder;
            _viewModel.VaultName = name;
            SetPasswordBuffer(secureBuffer);

            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => _viewModel.CreateVault());
        }

        [Fact]
        internal void RecievePasswordStringSetsBufferCorrectly()
        {
            byte[] predeterminedStringValue = new byte[] { 110, 0, 101, 0, 119, 0, 80, 0, 97, 0, 115, 0, 115, 0, 119, 0, 111, 0, 114, 0, 100, 0 }; //newPassword
            _viewModel.RecievePasswordString("newPassword");
            var newBuffer = (ISecureBuffer)_viewModel.GetType().GetField("_passwordBuffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(_viewModel)!;

            Assert.True(newBuffer.AsSpan.SequenceEqual(predeterminedStringValue));
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidStrings), MemberType = typeof(TestsHelper))]
        internal void RecievePasswordStringThrowsForInvalidString(string password, Type expectedException)
        {
            Assert.Throws(expectedException, () => _viewModel.RecievePasswordString(password));
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
