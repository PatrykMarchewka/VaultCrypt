using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt.Services
{
    public interface IFileService
    {
        /// <summary>
        /// Writes chunks to <paramref name="fileFS"/> in order
        /// </summary>
        /// <param name="results">Dictionary containing chunk number and chunk to write</param>
        /// <param name="nextToWrite">Number indicating which chunk should be written next</param>
        /// <param name="currentIndex">Number indicating which chunk got added with this method call</param>
        /// <param name="fileFS">Stream to write into</param>
        /// <param name="lockObject">Object acting as a lock to prevent multiple threads writing at the same time</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="results"/>, <paramref name="fileFS"/> or <paramref name="lockObject"/> is set to null</exception>
        /// <exception cref="VaultException">Thrown when chunk is missing from the <paramref name="results"/> despite being indicated with <paramref name="currentIndex"/></exception>
        public void WriteReadyChunk(ConcurrentDictionary<ulong, SecureBuffer.SecureLargeBuffer> results, ref ulong nextToWrite, ulong currentIndex, Stream fileFS, object lockObject);
        /// <summary>
        /// Replaces <paramref name="length"/> of bytes at <paramref name="offset"/> inside <paramref name="stream"/> with zeroes
        /// </summary>
        /// <param name="stream">Stream to write to</param>
        /// <param name="offset">Offset at which to start writing</param>
        /// <param name="length">Total number of bytes to replace</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="offset"/> is set to negative value or <paramref name="length"/> is set to zero</exception>
        public void ZeroOutPartOfFile(Stream stream, long offset, ulong length);
        /// <summary>
        /// Copies part of <paramref name="source"/> into <paramref name="destination"/>
        /// </summary>
        /// <param name="source">Stream to read from</param>
        /// <param name="offset">Offset at which to start reading</param>
        /// <param name="length">Length in bytes to read</param>
        /// <param name="destination">Stream to write into</param>
        /// <param name="destinationOffset">Offset at which to start writing</param>
        public void CopyPartOfFile(Stream source, long offset, ulong length, Stream destination, long destinationOffset);
    }

    public class FileService : IFileService
    {
        public void WriteReadyChunk(ConcurrentDictionary<ulong, SecureBuffer.SecureLargeBuffer> results, ref ulong nextToWrite, ulong currentIndex, Stream fileFS, object lockObject)
        {
            ArgumentNullException.ThrowIfNull(results);
            ArgumentOutOfRangeException.ThrowIfNegative(nextToWrite);
            ArgumentOutOfRangeException.ThrowIfNegative(currentIndex);
            ArgumentNullException.ThrowIfNull(fileFS);
            ArgumentNullException.ThrowIfNull(lockObject);
            lock (lockObject)
            {
                SecureBuffer.SecureLargeBuffer ready = null!;
                while (nextToWrite != currentIndex)
                {
                    Monitor.Wait(lockObject);
                }

                if (!results.TryRemove(nextToWrite, out ready!)) throw new VaultException(VaultException.ErrorContext.WriteToFile, VaultException.ErrorReason.MissingChunk);
                try
                {
                    fileFS.Write(ready.AsSpan);
                }
                finally
                {
                    ready.Dispose();
                }
                nextToWrite++;

                Monitor.PulseAll(lockObject);
            }
        }

        public void ZeroOutPartOfFile(Stream stream, long offset, ulong length)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfZero(length);

            Span<byte> zeroes = stackalloc byte[1024];
            stream.Seek(offset, SeekOrigin.Begin);
            while (length > 0)
            {
                //Length is provided as ulong to support fileSizes above 2GB
                int chunk = (int)Math.Min(length, (ulong)zeroes.Length);
                stream.Write(zeroes[..chunk]);
                length -= (ulong)chunk;
            }
        }

        public void CopyPartOfFile(Stream source, long offset, ulong length, Stream destination, long destinationOffset)
        {
            ArgumentNullException.ThrowIfNull(source);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfZero(length);
            ArgumentNullException.ThrowIfNull(destination);
            ArgumentOutOfRangeException.ThrowIfNegative(destinationOffset);

            source.Seek(offset, SeekOrigin.Begin);
            destination.Seek(destinationOffset, SeekOrigin.Begin);
            using (SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(8_388_608)) //8MB buffer
            {
                while (length > 0)
                {
                    //Length is provided as ulong to support fileSizes above 2GB
                    int chunkSize = (int)Math.Min(length, (ulong)buffer.Length);
                    var sliced = buffer.AsSpan.Slice(0, chunkSize);
                    source.ReadExactly(sliced);
                    destination.Write(sliced);
                    length -= (ulong)chunkSize;
                }
            }
        }
    }
}
