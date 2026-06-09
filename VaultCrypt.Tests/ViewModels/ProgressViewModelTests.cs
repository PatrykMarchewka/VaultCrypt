using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests.ViewModels
{
    public class ProgressViewModelTests
    {
        private readonly VaultCrypt.ViewModels.ProgressViewModel _viewModel;

        public ProgressViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.ProgressViewModel();
            _viewModel.Context = new();
        }

        [Fact]
        internal void FilteredTextRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.Context = new ProgressionContext();

            Assert.Equal(nameof(_viewModel.Context), changedProperty);
        }

        [Fact]
        internal void FilteredTextDoesNotRaisePropertyChanged()
        {
            ProgressionContext context = new();
            _viewModel.Context = context;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.Context = context;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void FilteredTextChangesValues()
        {
            ProgressionContext expected = new();
            _viewModel.Context = expected;

            Assert.Equal(expected, _viewModel.Context);
        }

        [Fact]
        internal void FinishCommandCanExecuteChanges()
        {
            Assert.False(_viewModel.FinishCommand.CanExecute(null));
            _viewModel.Context.Increment();
            Assert.True(_viewModel.FinishCommand.CanExecute(null));
            _viewModel.Context.SetTotal(100);
            Assert.False(_viewModel.FinishCommand.CanExecute(null));
        }

        [Fact]
        internal void FinishRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.Finish();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        internal void CancelCommandCanExecuteChanges()
        {
            Assert.True(_viewModel.CancelCommand.CanExecute(null));
            _viewModel.Context.Increment();
            Assert.False(_viewModel.CancelCommand.CanExecute(null));
            _viewModel.Context.SetTotal(100);
            Assert.True(_viewModel.CancelCommand.CanExecute(null));
        }

        [Fact]
        internal void CancelRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.Finish();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        internal void CancelRequestsCancellation()
        {
            _viewModel.Context = new();
            _viewModel.Cancel();
            Assert.True(_viewModel.Context.CancellationToken.IsCancellationRequested);
        }

        [Fact]
        internal void CanExecuteChangesOnContextUpdate()
        {
            //Event block to either return given item or wait desired time
            var eventBlock = new BlockingCollection<object>();

            int finishEventRaisedCount = 0;
            int cancelEventRaisedCount = 0;
            (_viewModel.FinishCommand as RelayCommand)!.CanExecuteChanged += (sender, args) => { Interlocked.Increment(ref finishEventRaisedCount); eventBlock.Add(new object()); };
            (_viewModel.CancelCommand as RelayCommand)!.CanExecuteChanged += (sender, args) => { Interlocked.Increment(ref cancelEventRaisedCount); eventBlock.Add(new object()); };
            _viewModel.Context.SetTotal(1);
            eventBlock.TryTake(out _, 1000);
            eventBlock.TryTake(out _, 1000);
            Assert.Equal(1, finishEventRaisedCount);
            Assert.Equal(1, cancelEventRaisedCount);

            _viewModel.Context.Increment();
            eventBlock.TryTake(out _, 1000);
            eventBlock.TryTake(out _, 1000);
            Assert.Equal(2, finishEventRaisedCount);
            Assert.Equal(2, cancelEventRaisedCount);

            _viewModel.Context.SetTotal(2);
            eventBlock.TryTake(out _, 1000);
            eventBlock.TryTake(out _, 1000);

            Assert.Equal(3, finishEventRaisedCount);
            Assert.Equal(3, cancelEventRaisedCount);
        }

        [Fact]
        internal void OnNavigatedToSetsValues()
        {
            ProgressionContext context = new ProgressionContext();
            _viewModel.OnNavigatedTo(context);

            Assert.Equal(context, _viewModel.Context);
            Assert.Empty(_viewModel.PermMessages);
        }

        public static TheoryData<object?, Type> InvalidParameters = new TheoryData<object?, Type>()
        {
            {null, typeof(ArgumentNullException) },
            {new(), typeof(ArgumentException) }
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
            _viewModel.NavigateBack();
            Assert.Equal(1, eventRaisedCount);
        }
    }
}
