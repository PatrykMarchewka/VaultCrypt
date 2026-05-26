using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class RelayCommandTests
    {
        [Fact]
        internal void ExecuteCallsAction()
        {
            bool called = false;
            var command = new RelayCommand(_ => called = true);

            command.Execute(null);

            Assert.True(called);
        }

        [Fact]
        internal async Task ExecuteCallsAsyncFunction()
        {
            var completionSource = new TaskCompletionSource();
            bool called = false;
            var command = new RelayCommand(async _ => { called = true; completionSource.SetResult(); });

            command.Execute(null);
            await completionSource.Task;

            Assert.True(called);
        }

        public static TheoryData<Exception> testException = new TheoryData<Exception>() { new Exception(), new ArgumentOutOfRangeException(), new ArgumentNullException(), new ArgumentException(), new VaultCrypt.Exceptions.VaultException(VaultCrypt.Exceptions.VaultException.ErrorContext.VaultSession, VaultCrypt.Exceptions.VaultException.ErrorReason.Other) };
        [Theory]
        [MemberData(nameof(testException))]
        internal void ExecuteCatchesExceptions(Exception ex)
        {
            Exception exception = null!;
            RelayCommand.SubscribeToExceptionThrowEvent(thrown => exception = thrown);

            var cmd = new RelayCommand(_ => throw ex);

            cmd.Execute(null);

            Assert.Same(ex, exception);
        }

        [Fact]
        internal void CanExecuteReturnsTrueForNoCondition()
        {
            var command = new RelayCommand(_ => { });

            Assert.True(command.CanExecute(null));
        }

        [Fact]
        internal void CanExecuteEvaluatesProperly()
        {
            var command = new RelayCommand(_ => { }, integer => (int)integer! > 0);

            Assert.True(command.CanExecute(1));
            Assert.False(command.CanExecute(0));
        }

        [Fact]
        internal void RaiseCanExecuteRaisesCanExecuteChanged()
        {
            var command = new RelayCommand(_ => { });
            bool eventCalled = false;
            command.CanExecuteChanged += (sender, args) => eventCalled = true;

            command.RaiseCanExecuteChanged();

            Assert.True(eventCalled);
        }
    }
}
