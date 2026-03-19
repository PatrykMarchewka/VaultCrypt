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
        private VaultCrypt.ViewModels.EncryptFileViewModel _viewModel;
        private readonly FakeEncryptionService fakeEncryptionService = new();

        public EncryptFileViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.EncryptFileViewModel(fakeEncryptionService);
        }

        [Fact]
        void ChunkSizePresetsInitializedCorrectly()
        {
            Assert.Equal(12, _viewModel.ChunkSizePresets.Count);

            Assert.Equal("1MB", _viewModel.ChunkSizePresets[0].Name);
            Assert.Equal(1, _viewModel.ChunkSizePresets[0].SizeInMB);
            Assert.Equal("2MB", _viewModel.ChunkSizePresets[1].Name);
            Assert.Equal(2, _viewModel.ChunkSizePresets[1].SizeInMB);
            Assert.Equal("4MB", _viewModel.ChunkSizePresets[2].Name);
            Assert.Equal(4, _viewModel.ChunkSizePresets[2].SizeInMB);
            Assert.Equal("8MB", _viewModel.ChunkSizePresets[3].Name);
            Assert.Equal(8, _viewModel.ChunkSizePresets[3].SizeInMB);
            Assert.Equal("16MB", _viewModel.ChunkSizePresets[4].Name);
            Assert.Equal(16, _viewModel.ChunkSizePresets[4].SizeInMB);
            Assert.Equal("32MB", _viewModel.ChunkSizePresets[5].Name);
            Assert.Equal(32, _viewModel.ChunkSizePresets[5].SizeInMB);
            Assert.Equal("64MB", _viewModel.ChunkSizePresets[6].Name);
            Assert.Equal(64, _viewModel.ChunkSizePresets[6].SizeInMB);
            Assert.Equal("128MB", _viewModel.ChunkSizePresets[7].Name);
            Assert.Equal(128, _viewModel.ChunkSizePresets[7].SizeInMB);
            Assert.Equal("256MB", _viewModel.ChunkSizePresets[8].Name);
            Assert.Equal(256, _viewModel.ChunkSizePresets[8].SizeInMB);
            Assert.Equal("512MB", _viewModel.ChunkSizePresets[9].Name);
            Assert.Equal(512, _viewModel.ChunkSizePresets[9].SizeInMB);
            Assert.Equal("1024MB", _viewModel.ChunkSizePresets[10].Name);
            Assert.Equal(1024, _viewModel.ChunkSizePresets[10].SizeInMB);
            Assert.Equal("2048MB", _viewModel.ChunkSizePresets[11].Name);
            Assert.Equal(2048, _viewModel.ChunkSizePresets[11].SizeInMB);
        }

        [Theory]
        [InlineData(0,1)]
        [InlineData(1,2)]
        [InlineData(2, 3)]
        [InlineData(3, 4)]
        [InlineData(4, 5)]
        [InlineData(5, 6)]
        [InlineData(6, 7)]
        [InlineData(7, 8)]
        [InlineData(8, 9)]
        [InlineData(9, 10)]
        [InlineData(10, 11)]
        void ChunkSizePresetsIncreaseInSize(int firstIndex, int secondIndex)
        {
            Assert.True(_viewModel.ChunkSizePresets[firstIndex].SizeInMB < _viewModel.ChunkSizePresets[secondIndex].SizeInMB);
        }

        [Fact]
        void SelectedPresetRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.SelectedPreset = _viewModel.ChunkSizePresets[1];

            Assert.Equal(nameof(_viewModel.SelectedPreset), changedProperty);
        }

        [Fact]
        void SelectedPresetDoesNotRaisePropertyChanged()
        {
            _viewModel.SelectedPreset = _viewModel.ChunkSizePresets[2];
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedPreset = _viewModel.ChunkSizePresets[2];

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void SelectedPresetChangesValue()
        {
            var expected = _viewModel.ChunkSizePresets[3];
            _viewModel.SelectedPreset = expected;

            Assert.Equal(expected, _viewModel.SelectedPreset);
        }

        [Fact]
        void SelectedAlgorithmRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.SelectedAlgorithm = _viewModel.EncryptionAlgorithms.Last();

            Assert.Equal(nameof(_viewModel.SelectedAlgorithm), changedProperty);
        }

        [Fact]
        void SelectedAlgorithmDoesNotRaisePropertyChanged()
        {
            _viewModel.SelectedAlgorithm = _viewModel.EncryptionAlgorithms.Last();
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.SelectedAlgorithm = _viewModel.EncryptionAlgorithms.Last();

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void SelectedAlgorithmChangesValue()
        {
            var expected = _viewModel.EncryptionAlgorithms.Last();
            _viewModel.SelectedAlgorithm = expected;

            Assert.Equal(expected, _viewModel.SelectedAlgorithm);
        }

        [Fact]
        async void EncryptRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            await _viewModel.Encrypt(NormalizedPath.From("value")!);

            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        async void EncryptCallsMethod()
        {
            await _viewModel.Encrypt(NormalizedPath.From("value")!);

            Assert.True(fakeEncryptionService.EncryptWasCalled);
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
