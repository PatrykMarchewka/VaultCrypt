using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class RetryHelperTests
    {

        [Fact]
        async Task TryUntilSuccessAsyncReturnsOnFirstTry()
        {
            string result = await RetryHelper.TryUntilSuccessAsync(
                tryAction: () => Task.FromResult("Success"),
                catchAction: () => { });

            Assert.Equal("Success", result);
        }

        [Fact]
        async Task TryUntilSuccessAsyncReturnsOnSecondTry()
        {
            int counter = 1;
            string result = await RetryHelper.TryUntilSuccessAsync(
                tryAction: () => { if (counter > 1) return Task.FromResult("Success"); throw new Exception(); },
                catchAction: () => counter++);

            Assert.Equal("Success", result);
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        void TryUntilSuccessAsyncThrowsOnInvalidMaxRetriesValue(int retries)
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => RetryHelper.TryUntilSuccessAsync(tryAction: () => { }, maxRetries: retries));
        }

        [Fact]
        void TryUntilSuccessAsyncThrowsOnMaxRetriesReached()
        {
            Assert.ThrowsAsync<VaultCrypt.Exceptions.VaultException>(() => RetryHelper.TryUntilSuccessAsync(tryAction: () => { throw new Exception(); }));
        }

        [Theory]
        [InlineData(typeof(Exception))]
        [InlineData(typeof(ArgumentNullException))]
        [InlineData(typeof(ArgumentOutOfRangeException))]
        void TryUntilSuccessAsyncThrowsOriginalExceptionOnFalseShouldRetry(Type exceptionType)
        {
            Assert.ThrowsAsync(exceptionType, () => RetryHelper.TryUntilSuccessAsync(tryAction: () => throw (Exception)Activator.CreateInstance(exceptionType)!, shouldRetry: ex => ex is not Exception));
        }

        [Fact]
        void TryUntilSuccessReturnsOnFirstTry()
        {
            string result = RetryHelper.TryUntilSuccess(tryAction: () => "Success");

            Assert.Equal("Success", result);
        }

        [Fact]
        void TryUntilSuccessReturnsOnSecondTry()
        {
            int counter = 1;
            string result = RetryHelper.TryUntilSuccess(
                tryAction: () => { if (counter > 1) return "Success"; throw new Exception(); },
                catchAction: () => counter++);

            Assert.Equal("Success", result);
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        void TryUntilSuccessThrowsOnInvalidMaxRetriesValue(int retries)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => RetryHelper.TryUntilSuccess(tryAction: () => { }, maxRetries: retries));
        }

        [Fact]
        void TryUntilSuccessThrowsOnMaxRetriesReached()
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultException>(() => RetryHelper.TryUntilSuccess(tryAction: () => { throw new Exception(); }));
        }

        [Theory]
        [InlineData(typeof(Exception))]
        [InlineData(typeof(ArgumentNullException))]
        [InlineData(typeof(ArgumentOutOfRangeException))]
        void TryUntilSuccessThrowsOriginalExceptionOnFalseShouldRetry(Type exceptionType)
        {
            Assert.Throws(exceptionType, () => RetryHelper.TryUntilSuccess(tryAction: () => throw (Exception)Activator.CreateInstance(exceptionType)!, shouldRetry: ex => ex is not Exception));
        }
    }
}
