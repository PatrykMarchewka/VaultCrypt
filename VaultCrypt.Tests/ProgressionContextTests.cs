using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.ViewModels;

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
            Assert.False(_progressionContext.CancellationToken.Equals(default));
        }

        [Fact]
        void IncrementIncreasesCompletedValue()
        {
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
            var progress = new Progress<ProgressionContext>(_ => { progressReported++; eventBlock.Add(new object()); }); 
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
        void SetTotalChangesValue()
        {
            _progressionContext.SetTotal(1);
            Assert.Equal(1UL, _progressionContext.Total);
            _progressionContext.SetTotal(2);
            Assert.Equal(2UL, _progressionContext.Total);
            _progressionContext.SetTotal(ulong.MaxValue);
            Assert.Equal(ulong.MaxValue, _progressionContext.Total);
        }

        [Fact]
        void SetTotalCallsProgressReport()
        {
            //Event block to either return given item or wait desired time
            var eventBlock = new BlockingCollection<object>();

            int progressReported = 0;
            var progress = new Progress<ProgressionContext>(_ => { progressReported++; eventBlock.Add(new object()); });
            _progressionContext.Progress = progress;

            _progressionContext.SetTotal(1);
            eventBlock.TryTake(out _, 1000);
            Assert.Equal(1, progressReported);
        }

        [Fact]
        void SetTotalThrowsOnZeroValue()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.SetTotal(0));
        }

        [Fact]
        void SetTotalThrowsOnNegativeValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.SetTotal(-1));
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.SetTotal(-2));
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.SetTotal(int.MinValue));
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
}
