using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests.ViewModels
{
    public class ExceptionThrownViewModelTests
    {
        private readonly VaultCrypt.ViewModels.ExceptionThrownViewModel _viewModel = new();

        [Fact]
        internal void ConstructorThrowsForInvalidParameters()
        {
            Assert.Throws<ArgumentNullException>(() => new VaultCrypt.ViewModels.ExceptionThrownViewModel(null!, new Exception()));
        }

        [Fact]
        internal void ExceptionMessageRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.ExceptionMessage = "raisedProperty";

            Assert.Equal(nameof(_viewModel.ExceptionMessage), changedProperty);
        }

        [Fact]
        internal void ExceptionMessagedDoesNotRaisePropertyChanged()
        {
            string message = "new";
            _viewModel.ExceptionMessage = message;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.ExceptionMessage = message;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void ExceptionMessageChangesValue()
        {
            string message = "changed";
            _viewModel.ExceptionMessage = message;

            Assert.Equal(message, _viewModel.ExceptionMessage);
        }

        [Fact]
        internal void InitializeInvokesAction()
        {
            var wasCalled = false;
            var vm = new VaultCrypt.ViewModels.ExceptionThrownViewModel(() => wasCalled = true);
            vm.OKCommand.Execute(null);

            Assert.True(wasCalled);
        }

        [Fact]
        internal void NavigationRequestedRaised()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.OKCommand.Execute(null);

            Assert.Equal(1, eventRaisedCount);
        }

        public static TheoryData<Exception?, string> OnNavigatedToValues = new TheoryData<Exception?, string>()
        {
            {new Exception("Expected value"), "Expected value" },
            {null, "Unknown error!" }
        };

        [Theory]
        [MemberData(nameof(OnNavigatedToValues))]
        internal void OnNavigatedToChangesValue(Exception? exception, string expectedMessage)
        {
            _viewModel.OnNavigatedTo(exception);

            Assert.Equal(_viewModel.ExceptionMessage, expectedMessage);
        }

        public static TheoryData<object?, Type> InvalidParameters = new TheoryData<object?, Type>()
        {
            {new(), typeof(ArgumentException) },
            {new Exception(""), typeof(ArgumentException) },
            {new Exception("    "), typeof(ArgumentException) }
        };

        [Theory]
        [MemberData(nameof(InvalidParameters))]
        internal void OnChangedToThrowsForInvalidParameters(object? parameters, Type expectedException)
        {
            Assert.Throws(expectedException, () => _viewModel.OnNavigatedTo(parameters));
        }
    }
}
