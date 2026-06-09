using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Tests.Services;

namespace VaultCrypt.Tests.ViewModels
{
    public class EncryptFileViewModelTests
    {
        private readonly VaultCrypt.ViewModels.EncryptFileViewModel _viewModel;
        private readonly FakeEncryptionService fakeEncryptionService = new();

        public EncryptFileViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.EncryptFileViewModel(fakeEncryptionService);
        }

        public static TheoryData<int, string, int> ChunkSizePresets = new TheoryData<int, string, int>()
        {
            {0, "1MB", 1 },
            {1, "2MB", 2 },
            {2, "4MB", 4 },
            {3, "8MB", 8 },
            {4, "16MB", 16 },
            {5, "32MB", 32 },
            {6, "64MB", 64 },
            {7, "128MB", 128 },
            {8, "256MB", 256 },
            {9, "512MB", 512 },
            {10, "1024MB", 1024 },
            {11, "2048MB", 2048 }
        };

        [Fact]
        internal void ChunkSizePresetsHasCorrectAmountOfItems()
        {
            Assert.Equal(ChunkSizePresets.Count(), _viewModel.ChunkSizePresets.Count);
        }

        [Theory]
        [MemberData(nameof(ChunkSizePresets))]
        internal void ChunkSizePresetsInitializedCorrectly(int position, string name, int sizeInMB)
        {
            Assert.Equal(name, _viewModel.ChunkSizePresets[position].Name);
            Assert.Equal(sizeInMB, _viewModel.ChunkSizePresets[position].SizeInMB);
        }

        [Theory]
        [MemberData(nameof(ChunkSizePresets))]
        internal void ChunkSizeHaveUniqueValues(int _, string name, int sizeInMB)
        {
            Assert.Single(_viewModel.ChunkSizePresets.Where(preset => preset.Name == name));
            Assert.Single(_viewModel.ChunkSizePresets.Where(preset => preset.SizeInMB == sizeInMB));
        }

        [Fact]
        internal void ChunkSizePresetsIncreaseInSize()
        {
            for (int i = 1; i < _viewModel.ChunkSizePresets.Count; i++)
            {
                Assert.True(_viewModel.ChunkSizePresets[i].SizeInMB > _viewModel.ChunkSizePresets[i - 1].SizeInMB);
            }
        }

        [Fact]
        internal void SelectedPresetRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.SelectedPreset = _viewModel.ChunkSizePresets[1];

            Assert.Equal(nameof(_viewModel.SelectedPreset), changedProperty);
        }

        [Fact]
        internal void SelectedPresetDoesNotRaisePropertyChanged()
        {
            _viewModel.SelectedPreset = _viewModel.ChunkSizePresets[2];
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedPreset = _viewModel.ChunkSizePresets[2];

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void SelectedPresetChangesValue()
        {
            var expected = _viewModel.ChunkSizePresets[3];
            _viewModel.SelectedPreset = expected;

            Assert.Equal(expected, _viewModel.SelectedPreset);
        }

        [Fact]
        internal void SelectedAlgorithmRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.SelectedAlgorithm = _viewModel.EncryptionAlgorithms.Last();

            Assert.Equal(nameof(_viewModel.SelectedAlgorithm), changedProperty);
        }

        [Fact]
        internal void SelectedAlgorithmDoesNotRaisePropertyChanged()
        {
            _viewModel.SelectedAlgorithm = _viewModel.EncryptionAlgorithms.Last();
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedAlgorithm = _viewModel.EncryptionAlgorithms.Last();

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void SelectedAlgorithmChangesValue()
        {
            var expected = _viewModel.EncryptionAlgorithms.Last();
            _viewModel.SelectedAlgorithm = expected;

            Assert.Equal(expected, _viewModel.SelectedAlgorithm);
        }

        [Fact]
        internal async void EncryptRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.Encrypt(NormalizedPath.From("value")!);

            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        internal async void EncryptCallsMethod()
        {
            await _viewModel.Encrypt(NormalizedPath.From("value")!);

            Assert.True(fakeEncryptionService.EncryptWasCalled);
        }

        [Fact]
        internal void OnNavigatedToSetsValues()
        {
            NormalizedPath expected = NormalizedPath.From("OnNavigatedToTest");
            _viewModel.OnNavigatedTo(expected);

            //Reflection because _viewmodel.filePath is private
            //TODO: Replace reflection with something better
            NormalizedPath actual = (NormalizedPath)_viewModel.GetType().GetField("filePath", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(_viewModel)!;
            Assert.Equal(expected, actual);
        }

        public static TheoryData<object?, Type> InvalidParameters = new TheoryData<object?, Type>()
        {
            {null, typeof(ArgumentNullException) },
            {new(), typeof(ArgumentException) },
            {NormalizedPath.From(""), typeof(ArgumentException) },
            {NormalizedPath.From("  "), typeof(ArgumentException) }
        };

        [Theory]
        [MemberData(nameof(InvalidParameters))]
        internal void OnNavigatedToThrowsForInvalidParameters(object? parameters, Type expectedException)
        {
            Assert.Throws(expectedException, () => _viewModel.OnNavigatedTo(parameters!));
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
