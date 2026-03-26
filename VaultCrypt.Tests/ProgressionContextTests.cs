using System;
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
            SynchronizationContext.SetSynchronizationContext(null);
            _progressionContext = new ProgressionContext();
        }

        [Fact]
        void CompletedRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _progressionContext.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _progressionContext.Completed = 1;

            Assert.Equal(nameof(_progressionContext.Completed), changedProperty);
        }

        [Fact]
        void CompletedDoesNotRaisePropertyChanged()
        {
            _progressionContext.Completed = 1;
            int eventRaisedCount = 0;
            _progressionContext.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _progressionContext.Completed = 1;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void CompletedChangesValue()
        {
            ulong expected = 5;
            _progressionContext.Completed = expected;

            Assert.Equal(expected, _progressionContext.Completed);
        }

        [Fact]
        void TotalRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _progressionContext.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _progressionContext.Total = 10;

            Assert.Equal(nameof(_progressionContext.Total), changedProperty);
        }

        [Fact]
        void TotalDoesNotRaisePropertyChanged()
        {
            _progressionContext.Total = 10;
            int eventRaisedCount = 0;
            _progressionContext.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _progressionContext.Total = 10;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void TotalChangesValue()
        {
            ulong expected = 5;
            _progressionContext.Total = expected;

            Assert.Equal(expected, _progressionContext.Total);
        }

        [Theory]
        [InlineData(1,2)]
        [InlineData(2,2)]
        [InlineData(0, ulong.MaxValue)]
        [InlineData(ulong.MaxValue, ulong.MaxValue)]
        async Task CompletedAndTotalAreSetCorrectly(ulong completed, ulong total)
        {
            _progressionContext.Progress.Report(new ProgressStatus(completed, total));

            //Wait until values are set or until 100ms passes
            System.Threading.SpinWait.SpinUntil(() => _progressionContext.Completed == completed, 100);
            System.Threading.SpinWait.SpinUntil(() => _progressionContext.Total == total, 100);

            Assert.Equal(completed, _progressionContext.Completed);
            Assert.Equal(total, _progressionContext.Total);
        }

        [Theory]
        [InlineData(int.MinValue, 0)]
        [InlineData(-1, 0)]
        [InlineData(0, int.MinValue)]
        [InlineData(0, -1)]
        [InlineData(int.MinValue, int.MinValue)]
        [InlineData(-1, -1)]
        void ProgressStatusThrowsOnNegativeValues(int completed, int total)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.Progress.Report(new ProgressStatus(completed, total)));
        }

        [Fact]
        void ProgressStatusThrowsOnZeroTotal()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _progressionContext.Progress.Report(new ProgressStatus(0, 0)));
        }
    }
}
