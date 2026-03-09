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
        void ExecuteCallsAction()
        {
            bool called = false;
            var command = new RelayCommand(_ => called = true);

            command.Execute(null);

            Assert.True(called);
        }

        [Fact]
        async Task ExecuteCallsAsyncFunction()
        {
            bool called = false;
            var command = new RelayCommand(async _ => { await Task.Delay(1); called = true; });

            command.Execute(null);
            await Task.Delay(100); //Waiting for async method to complete

            Assert.True(called);
        }

        public static TheoryData<Exception> testException = new TheoryData<Exception>() { new Exception(), new ArgumentOutOfRangeException(), new ArgumentNullException(), new ArgumentException(), new VaultCrypt.Exceptions.VaultException(VaultCrypt.Exceptions.VaultException.ErrorContext.VaultSession, VaultCrypt.Exceptions.VaultException.ErrorReason.Other) };
        [Theory]
        [MemberData(nameof(testException))]
        void ExecuteCatchesExceptions(Exception ex)
        {
            Exception exception = null!;
            RelayCommand.SubscribeToExceptionThrowEvent(thrown => exception = thrown);

            var cmd = new RelayCommand(_ => throw ex);

            cmd.Execute(null);

            Assert.Same(ex, exception);
        }

        [Fact]
        void CanExecuteReturnsTrueForNoCondition()
        {
            var command = new RelayCommand(_ => { });

            Assert.True(command.CanExecute(null));
        }

        [Fact]
        void CanExecuteEvaluatesProperly()
        {
            var command = new RelayCommand(_ => { }, integer => (int)integer! > 0);

            Assert.True(command.CanExecute(1));
            Assert.False(command.CanExecute(0));
        }

        [Fact]
        void RaiseCanExecuteRaisesCanExecuteChanged()
        {
            var command = new RelayCommand(_ => { });
            bool eventCalled = false;
            command.CanExecuteChanged += (sender, args) => eventCalled = true;

            command.RaiseCanExecuteChanged();

            Assert.True(eventCalled);
        }
    }
}
