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
        void WriteReadyChunk(ConcurrentDictionary<int, byte[]> results, ref int nextToWrite, int currentIndex, Stream fileFS, object lockObject);
        void ZeroOutPartOfFile(Stream stream, long offset, ulong length);
        void CopyPartOfFile(Stream source, long offset, ulong length, Stream destination, long destinationOffset);
    }

    public class FileService : IFileService
    {
        public void WriteReadyChunk(ConcurrentDictionary<int, byte[]> results, ref int nextToWrite, int currentIndex, Stream fileFS, object lockObject)
        {
            ArgumentNullException.ThrowIfNull(results);
            ArgumentOutOfRangeException.ThrowIfNegative(nextToWrite);
            ArgumentOutOfRangeException.ThrowIfNegative(currentIndex);
            ArgumentNullException.ThrowIfNull(fileFS);
            ArgumentNullException.ThrowIfNull(lockObject);
            lock (lockObject)
            {
                byte[] ready;
                while (nextToWrite != currentIndex)
                {
                    Monitor.Wait(lockObject);
                }

                if (!results.TryRemove(nextToWrite, out ready!)) throw new VaultException(VaultException.ErrorContext.WriteToFile, VaultException.ErrorReason.MissingChunk);
                try
                {
                    fileFS.Write(ready, 0, ready.Length);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ready);
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

            //8MB buffer
            byte[] buffer = new byte[8_388_608];

            source.Seek(offset, SeekOrigin.Begin);
            destination.Seek(destinationOffset, SeekOrigin.Begin);
            try
            {
                while (length > 0)
                {
                    //Length is provided as ulong to support fileSizes above 2GB
                    int chunkSize = (int)Math.Min(length, (ulong)buffer.Length);
                    source.ReadExactly(buffer, 0, chunkSize);
                    destination.Write(buffer, 0, chunkSize);
                    length -= (ulong)chunkSize;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }

        }
    }
}
