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
        /// <see cref="Progress"/> needs to be set by viewmodel that uses <see cref="ProgressReported"/> <br/>
        /// Left as nullable to avoid counting progression without having viewmodel attached
        /// </remarks>
        public IProgress<ProgressReported>? Progress { get; set; }

        private readonly CancellationTokenSource _cancellationTokenSource = new();
        public CancellationToken CancellationToken { get; }

        public ProgressionContext()
        {
            _completed = 0;
            _total = 1; //Starting at 1 so user sees 0/1 instead 0/0
            CancellationToken = _cancellationTokenSource.Token;
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
            Progress?.Report(new ProgressReported());
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
            Progress?.Report(new ProgressReported());
        }

        /// <inheritdoc cref="SetTotal(ulong)"/>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="total"/> is set to negative value</exception>
        public void SetTotal(int total)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(total);
            SetTotal((ulong)total);
        }
        /// <summary>
        /// Reports <paramref name="failure"/> with attached message and calls <see cref="IProgress{T}.Report(T)"/> to update the UI
        /// </summary>
        /// <param name="failure">Failure to report</param>
        /// <param name="message">Additional message to add while reporting</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is set to null</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="message"/> is empty or <paramref name="failure"/> is set to <see cref="ProgressFailure.ProgressPermFailure.None"/></exception>
        public void ReportPermStatus(ProgressFailure.ProgressPermFailure failure, string message)
        {
            ArgumentException.ThrowIfNullOrEmpty(message);
            if (failure.Equals(ProgressFailure.ProgressPermFailure.None)) throw new ArgumentException("Cannot report message with failure state being set to none", nameof(failure));

            string preparedMessage = $"{ProgressFailure.GetMessage(failure)} {message}";
            Progress?.Report(new ProgressReported(message: preparedMessage));
        }

        /// <inheritdoc cref="ReportPermStatus(ProgressFailure.ProgressPermFailure, string)"/>
        /// <param name="number">Number of a Task that failed</param>
        public void ReportPermStatus(ProgressFailure.ProgressPermFailure failure, ulong number = 0)
        {
            ReportPermStatus(failure, $"#{number}");
        }

        /// <inheritdoc cref="ReportPermStatus(ProgressFailure.ProgressPermFailure, ulong)"/>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="number"/> is set to negative value</exception>
        public void ReportPermStatus(ProgressFailure.ProgressPermFailure failure, int number = 0)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(number);
            ReportPermStatus(failure, (ulong)number);
        }

        /// <summary>
        /// Reports <paramref name="failure"/> and calls <see cref="IProgress{T}.Report(T)"/> to update the UI
        /// </summary>
        /// <param name="failure">Failure to report</param>
        /// <exception cref="ArgumentException">Thrown when <paramref name="failure"/> is set to <see cref="ProgressFailure.ProgressTempFailure.None"/></exception>
        public void ReportTempStatus(ProgressFailure.ProgressTempFailure failure)
        {
            if(failure.Equals(ProgressFailure.ProgressTempFailure.None)) throw new ArgumentException("Cannot report message with failure state being set to none", nameof(failure));

            string preparedTempMessage = $"{ProgressFailure.GetMessage(failure)} Retrying...";
            Progress?.Report(new ProgressReported(tempMessage: preparedTempMessage));
        }

        /// <summary>
        /// Creates a request to cancel operation
        /// </summary>
        public void Cancel() => _cancellationTokenSource.Cancel();

        public void Dispose()
        {
            _cancellationTokenSource.Dispose();
        }
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

    /// <summary>
    /// Snapshot holding messages regarding progress to display
    /// </summary>
    public sealed record ProgressReported
    {
        /// <summary>
        /// Message to display that should stay even if the issue passes
        /// </summary>
        public string? Message { get; }
        /// <summary>
        /// Message to display, indicates that message should be only visible during the current issue and get cleared once it passed
        /// </summary>
        public string? TempMessage { get; }

        public ProgressReported(string? message = null, string? tempMessage = null)
        {
            Message = message;
            TempMessage = tempMessage;
        }
    }
}
