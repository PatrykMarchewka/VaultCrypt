using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Tests.ViewModels
{
    public class ProgressViewModelTests
    {
        private VaultCrypt.ViewModels.ProgressViewModel _viewModel;

        public ProgressViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.ProgressViewModel();
        }

        [Fact]
        void FilteredTextRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.Context = new ProgressionContext();

            Assert.Equal(nameof(_viewModel.Context), changedProperty);
        }

        [Fact]
        void FilteredTextDoesNotRaisePropertyChanged()
        {
            ProgressionContext context = new();
            _viewModel.Context = context;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.Context = context;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void FilteredTextChangesValues()
        {
            ProgressionContext expected = new() { Completed = 1, Total = 999 };
            _viewModel.Context = expected;

            Assert.Equal(expected, _viewModel.Context);
        }

        [Fact]
        void FinishCommandCanExecuteChanges()
        {
            int eventRaisedCount = 0;
            (_viewModel.FinishCommand as RelayCommand)!.CanExecuteChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.Context = new() { Completed = 1};
            _viewModel.Context.Total = 1;
            Assert.Equal(1, eventRaisedCount);
            Assert.True(_viewModel.FinishCommand.CanExecute(null));

            _viewModel.Context = new() { Completed = 1 };
            _viewModel.Context.Total = 2;
            Assert.Equal(2, eventRaisedCount);
            Assert.False(_viewModel.FinishCommand.CanExecute(null));
        }

        [Fact]
        void CancelCommandCanExecuteChanges()
        {
            int eventRaisedCount = 0;
            (_viewModel.CancelCommand as RelayCommand)!.CanExecuteChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.Context = new() { Completed = 1 };
            _viewModel.Context.Total = 2;
            Assert.Equal(1, eventRaisedCount);
            Assert.True(_viewModel.CancelCommand.CanExecute(null));

            _viewModel.Context = new() { Completed = 1 };
            _viewModel.Context.Total = 1;
            Assert.Equal(2, eventRaisedCount);
            Assert.False(_viewModel.CancelCommand.CanExecute(null));
        }

        [Fact]
        void FinishRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.Finish();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        void CancelRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.Finish();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        void CancelRequestsCancellation()
        {
            _viewModel.Context = new();
            _viewModel.Cancel();
            Assert.True(_viewModel.Context.CancellationToken.IsCancellationRequested);
        }

        [Fact]
        void NavigationRequestedRaised()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.NavigateBack();
            Assert.Equal(1, eventRaisedCount);
        }
    }
}
