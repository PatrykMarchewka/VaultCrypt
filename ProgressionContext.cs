using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    public class ProgressionContext : IDisposable
    {
        private ulong _completed;
        public ulong Completed => _completed;

        private ulong _total;
        public ulong Total => _total;

        /// <summary>
        /// <see cref="IProgress{T}"/> instance to update the UI via <see cref="IProgress{T}.Report(T)"/>
        /// </summary>
        /// <remarks>
        /// <see cref="Progress"/> needs to be set by viewmodel that uses <see cref="ProgressionContext"/> <br/>
        /// Left as nullable to avoid counting progression without having viewmodel attached
        /// </remarks>
        public IProgress<ProgressionContext>? Progress { get; set; }

        private readonly CancellationTokenSource _cancellationTokenSource = new();
        public CancellationToken CancellationToken => _cancellationTokenSource.Token;

        public ProgressionContext()
        {
            _completed = 0;
            _total = 1; //Starting at 1 so user sees 0/1 instead 0/0
        }

        /// <summary>
        /// Increments <see cref="Completed"/> value by <paramref name="amount"/> atomically and calls <see cref="IProgress{T}.Report(T)"/> to update the UI
        /// </summary>
        /// <param name="amount">Amount to increment</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="amount"/> is set to zero</exception>
        public void Increment(ulong amount = 1)
        {
            ArgumentOutOfRangeException.ThrowIfZero(amount);
            Interlocked.Add(ref _completed, amount);
            Progress?.Report(this);
        }

        /// <summary>
        /// Sets the <see cref="Total"/> atomically to <paramref name="total"/> and calls <see cref="IProgress{T}.Report(T)"/> to update the UI
        /// </summary>
        /// <param name="total">New value to set</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="total"/> is set to zero</exception>
        public void SetTotal(ulong total)
        {
            ArgumentOutOfRangeException.ThrowIfZero(total);
            Interlocked.Exchange(ref _total, total);
            Progress?.Report(this);
        }

        /// <inheritdoc cref="SetTotal(ulong)"/>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="total"/> is set to negative value</exception>
        public void SetTotal(int total)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(total);
            SetTotal((ulong)total);
        }

        /// <summary>
        /// Creates a request to cancel operation
        /// </summary>
        public void Cancel() => _cancellationTokenSource.Cancel();

        public void Dispose()
        {
            _cancellationTokenSource.Dispose();
        }

        ~ProgressionContext()
        {
            Dispose();
        }

    public sealed class ProgressFailure()
    {
        public enum ProgressPermFailure
        {
            None,
            ChunkDecryptFailed,
            FileMetadataDecryptFailed,
            UnexpectedEndOfStream
        }

        public enum ProgressTempFailure
        {
            None,
            ReadingFromStreamFailed,
            WritingToFileFailed
        }

        public static string GetMessage(ProgressPermFailure failure) => failure switch
        {
            ProgressPermFailure.None => string.Empty,
            ProgressPermFailure.ChunkDecryptFailed => "Failed to decrypt chunk",
            ProgressPermFailure.FileMetadataDecryptFailed => "Failed to decrypt metadata for file",
            ProgressPermFailure.UnexpectedEndOfStream => "Unexpected end of stream",
            _ => "Unknown error!"
        };

        public static string GetMessage(ProgressTempFailure failure) => failure switch
        {
            ProgressTempFailure.None => string.Empty,
            ProgressTempFailure.ReadingFromStreamFailed => "Failed to read required information from stream",
            ProgressTempFailure.WritingToFileFailed => "Failed writing to file",
            _ => "Unknown error!"
        };
    }
}
