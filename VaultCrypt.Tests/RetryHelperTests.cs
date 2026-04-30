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
        async Task TryUntilSuccessReturnsOnFirstTryAsync()
        {
            string result = await RetryHelper.TryUntilSuccess(
                tryAction: () => Task.FromResult("Success"),
                catchAction: () => { });

            Assert.Equal("Success", result);
        }

        [Fact]
        void TryUntilSuccessReturnsOnFirstTrySync()
        {
            string result = RetryHelper.TryUntilSuccess(tryAction: () => "Success").ConfigureAwait(false).GetAwaiter().GetResult();

            Assert.Equal("Success", result);
        }

        [Fact]
        async Task TryUntilSuccessReturnsOnSecondTryAsync()
        {
            int counter = 1;
            string result = await RetryHelper.TryUntilSuccess(
                tryAction: () => { if (counter > 1) return Task.FromResult("Success"); throw new Exception(); },
                catchAction: () => counter++);

            Assert.Equal("Success", result);
        }

        [Fact]
        void TryUntilSuccessReturnsOnSecondTrySync()
        {
            int counter = 1;
            string result = RetryHelper.TryUntilSuccess(tryAction: () => { if (counter > 1) return "Success"; throw new Exception(); }, catchAction: () => counter++).ConfigureAwait(false).GetAwaiter().GetResult();

            Assert.Equal("Success", result);
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        void TryUntilSuccessThrowsOnInvalidMaxRetriesValue(int retries)
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => RetryHelper.TryUntilSuccess(tryAction: () => { }, maxRetries: retries));
        }

        [Fact]
        void TryUntilSuccessThrowsOnMaxRetriesReached()
        {
            Assert.ThrowsAsync<VaultCrypt.Exceptions.VaultException>(() => RetryHelper.TryUntilSuccess(tryAction: () => { throw new Exception(); }));
        }

        [Theory]
        [InlineData(typeof(Exception))]
        [InlineData(typeof(ArgumentNullException))]
        [InlineData(typeof(ArgumentOutOfRangeException))]
        void TryUntilSuccessThrowsOriginalExceptionOnFalseShouldRetry(Type exceptionType)
        {
            Assert.ThrowsAsync(exceptionType, () => RetryHelper.TryUntilSuccess(tryAction: () => throw (Exception)Activator.CreateInstance(exceptionType)!, shouldRetry: ex => ex is not Exception));
        }
    }
}
