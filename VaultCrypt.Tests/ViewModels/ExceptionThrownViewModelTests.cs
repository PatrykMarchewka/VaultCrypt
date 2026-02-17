using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests.ViewModels
{
    public class ExceptionThrownViewModelTests
    {
        private VaultCrypt.ViewModels.ExceptionThrownViewModel _viewModel;

        public ExceptionThrownViewModelTests()
        {
            this._viewModel = new();
        }

        [Fact]
        void ExceptionMessageRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.ExceptionMessage = "raisedProperty";

            Assert.Equal(nameof(_viewModel.ExceptionMessage), changedProperty);
        }

        [Fact]
        void ExceptionMessagedDoesNotRaisePropertyChanged()
        {
            string message = "new";
            _viewModel.ExceptionMessage = message;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.ExceptionMessage = message;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void ExceptionMessageChangesValue()
        {
            string message = "changed";
            _viewModel.ExceptionMessage = message;

            Assert.Equal(message, _viewModel.ExceptionMessage);
        }

        [Fact]
        void InitializeInvokesAction()
        {
            var wasCalled = false;
            var vm = new VaultCrypt.ViewModels.ExceptionThrownViewModel(() => wasCalled = true);
            vm.OKCommand.Execute(null);

            Assert.True(wasCalled);
        }

        [Fact]
        void NavigationRequestedRaised()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.OKCommand.Execute(null);

            Assert.Equal(1, eventRaisedCount);
        }


        public static TheoryData<Exception?> testException = new TheoryData<Exception?>() { new Exception(), null };
        [Theory]
        [MemberData(nameof(testException))]
        void OnNavigatedToChangesValue(Exception? exception)
        {
            _viewModel.OnNavigatedTo(exception);

            Assert.Equal(_viewModel.ExceptionMessage, exception?.Message ?? "Unknown error!");
        }
    }
}
