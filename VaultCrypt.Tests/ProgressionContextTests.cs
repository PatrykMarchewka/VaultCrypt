using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class ProgressionContextTests
    {
        ProgressionContext _progressionContext;

        public ProgressionContextTests()
        {
            _progressionContext = new ProgressionContext();
        }

        [Fact]
        void ProgressionContextInitializesCorrectly()
        {
            Assert.Equal(0UL, _progressionContext.Completed);
            Assert.Equal(1UL, _progressionContext.Total);
            Assert.Null(_progressionContext.Progress);
            Assert.False(_progressionContext.CancellationToken.Equals(default));
        }

        [Fact]
        void IncrementIncreasesCompletedValue()
        {
            _progressionContext.SetTotal(ulong.MaxValue);
            _progressionContext.Increment(ulong.MaxValue);
            Assert.Equal(ulong.MaxValue, _progressionContext.Completed);
            _progressionContext.Increment();
            Assert.Equal(0UL, _progressionContext.Completed);
            _progressionContext.Increment(2);
            Assert.Equal(2UL, _progressionContext.Completed);
        }

        [Fact]
        void IncrementCallsProgressReport()
        {
            //Event block to either return given item or wait desired time
            var eventBlock = new BlockingCollection<object>();

            int progressReported = 0;
            var progress = new Progress<ProgressReported>(_ => { progressReported++; eventBlock.Add(new object()); }); 
            _progressionContext.Progress = progress;

            _progressionContext.Increment();
            eventBlock.TryTake(out _, 1000);
            Assert.Equal(1, progressReported);
        }

        [Fact]
        void IncrementThrowsOnZeroValue()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.Increment(0));
        }

        [Fact]
        void IncrementThrowsOnCompletedGreaterThanTotal()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.Increment(int.MaxValue));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(ulong.MaxValue)]
        void SetTotalChangesValue(ulong total)
        {
            _progressionContext.SetTotal(total);
            Assert.Equal(total, _progressionContext.Total);
        }

        [Fact]
        void SetTotalCallsProgressReport()
        {
            //Event block to either return given item or wait desired time
            var eventBlock = new BlockingCollection<object>();

            int progressReported = 0;
            var progress = new Progress<ProgressReported>(_ => { progressReported++; eventBlock.Add(new object()); });
            _progressionContext.Progress = progress;

            _progressionContext.SetTotal(1);
            eventBlock.TryTake(out _, 1000);
            Assert.Equal(1, progressReported);
        }

        [Fact]
        void SetTotalThrowsOnTotalLessThanCompleted()
        {
            int total = 100;
            _progressionContext.SetTotal(total);
            _progressionContext.Increment((ulong)total);
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.SetTotal(total - 1));
        }

        [Fact]
        void SetTotalThrowsOnZeroTotal()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.SetTotal(0));
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(-2)]
        [InlineData(int.MinValue)]
        void SetTotalThrowsOnNegativeTotal(int total)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.SetTotal(total));
        }

        [Fact]
        void ForceFinishSetsCompletedToTotal()
        {
            ulong value = 1000;
            _progressionContext.SetTotal(value);

            _progressionContext.ForceFinish();

            Assert.Equal(value, _progressionContext.Completed);
            Assert.Equal(value, _progressionContext.Total);
        }

        [Fact]
        void ForceFinishCallsProgressReport()
        {
            //Event block to either return given item or wait desired time
            var eventBlock = new BlockingCollection<object>();

            int progressReported = 0;
            var progress = new Progress<ProgressReported>(_ => { progressReported++; eventBlock.Add(new object()); });
            _progressionContext.Progress = progress;

            _progressionContext.ForceFinish();
            eventBlock.TryTake(out _, 1000);
            Assert.Equal(1, progressReported);
        }

        [Fact]
        void ReportPermStatusCallsProgressReport()
        {
            //Event block to either return given item or wait desired time
            var eventBlock = new BlockingCollection<object>();

            int progressReported = 0;
            var progress = new Progress<ProgressReported>(_ => { progressReported++; eventBlock.Add(new object()); });
            _progressionContext.Progress = progress;

            _progressionContext.ReportPermStatus((ProgressFailure.ProgressPermFailure)1, "message");
            eventBlock.TryTake(out _, 1000);
            Assert.Equal(1, progressReported);
        }

        [Fact]
        void ReportPermStatusThrowsOnNullMessage()
        {
            Assert.Throws<ArgumentNullException>(() => _progressionContext.ReportPermStatus((ProgressFailure.ProgressPermFailure)1, null!));
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        void ReportPermStatusThrowsOnInvalidMessage(string message)
        {
            Assert.Throws<ArgumentException>(() => _progressionContext.ReportPermStatus((ProgressFailure.ProgressPermFailure)1, message));
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(int.MinValue)]
        void ReportPermStatusThrowsOnNegativeNumber(int number)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.ReportPermStatus((ProgressFailure.ProgressPermFailure)1, number));
        }

        [Theory]
        [InlineData(default(ProgressFailure.ProgressPermFailure))]
        void ReportPermStatusThrowsOnInvalidFailure(ProgressFailure.ProgressPermFailure failure)
        {
            Assert.Throws<ArgumentException>(() => _progressionContext.ReportPermStatus(failure, "message"));
        }

        [Fact]
        void ReportTempStatusCallsProgressReport()
        {
            //Event block to either return given item or wait desired time
            var eventBlock = new BlockingCollection<object>();

            int progressReported = 0;
            var progress = new Progress<ProgressReported>(_ => { progressReported++; eventBlock.Add(new object()); });
            _progressionContext.Progress = progress;

            _progressionContext.ReportTempStatus((ProgressFailure.ProgressTempFailure)1);
            eventBlock.TryTake(out _, 1000);
            Assert.Equal(1, progressReported);
        }

        [Theory]
        [InlineData(default(ProgressFailure.ProgressTempFailure))]
        void ReportTempStatusThrowsOnInvalidFailure(ProgressFailure.ProgressTempFailure failure)
        {
            Assert.Throws<ArgumentException>(() => _progressionContext.ReportTempStatus(failure));
        }

        [Fact]
        void CancelUpdatesToken()
        {
            _progressionContext.Cancel();
            Assert.True(_progressionContext.CancellationToken.IsCancellationRequested);
        }

        [Fact]
        void DisposeClearsValues()
        {
            _progressionContext.Dispose();
            Assert.Throws<ObjectDisposedException>(() => _progressionContext.CancellationToken);
        }
    }

    public class ProgressFailureTests()
    {
        [Fact]
        void GetMessageReturnsCorrectPermFailureString()
        {
            string expected = "Failed to decrypt chunk";
            string actual = ProgressFailure.GetMessage(ProgressFailure.ProgressPermFailure.ChunkDecryptFailed);
            Assert.Equal(expected, actual);
        }

        [Fact]
        void GetMessageReturnsCorrectDefaultPermFailureString()
        {
            string expected = string.Empty;
            string actual = ProgressFailure.GetMessage(default(ProgressFailure.ProgressPermFailure));
            Assert.Equal(expected, actual);
        }

        [Fact]
        void GetMessageReturnsCorrectFallbackPermFailureString()
        {
            string expected = "Unknown error!";
            string actual = ProgressFailure.GetMessage((ProgressFailure.ProgressPermFailure)int.MaxValue);
            Assert.Equal(expected, actual);
        }

        [Fact]
        void GetMessageReturnsCorrectTempFailureString()
        {
            string expected = "Failed to read required information from stream";
            string actual = ProgressFailure.GetMessage(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed);
            Assert.Equal(expected, actual);
        }

        [Fact]
        void GetMessageReturnsCorrectDefaultTempFailureString()
        {
            string expected = string.Empty;
            string actual = ProgressFailure.GetMessage(default(ProgressFailure.ProgressTempFailure));
            Assert.Equal(expected, actual);
        }

        [Fact]
        void GetMessageReturnsCorrectFallbackTempFailureString()
        {
            string expected = "Unknown error!";
            string actual = ProgressFailure.GetMessage((ProgressFailure.ProgressPermFailure)int.MaxValue);
            Assert.Equal(expected, actual);
        }
    }
}
