using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Tests.ViewModels
{
    public class MainWindowViewModelTests
    {
        private VaultCrypt.ViewModels.MainWindowViewModel _viewModel;

        public MainWindowViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.MainWindowViewModel();
        }

        [Fact]
        void CurrentViewRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.CurrentView = new FakeViewModel();

            Assert.Equal(nameof(_viewModel.CurrentView), changedProperty);
        }

        [Fact]
        void CurrentViewDoesNotRaisePropertyChanged()
        {
            IViewModel fake = new FakeViewModel();
            _viewModel.CurrentView = fake;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.CurrentView = fake;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void CurrentViewChangesValue()
        {
            IViewModel expected = new FakeViewModel();
            _viewModel.CurrentView = expected;

            Assert.Equal(expected, _viewModel.CurrentView);
        }

    }
}
