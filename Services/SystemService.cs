using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt.Services
{
    public interface ISystemService
    {
        /// <summary>
        /// Checks whether there is enough free space on <see cref="IVaultSession.VAULTPATH"/> drive to perform operation
        /// </summary>
        /// <param name="filePath">Path of the file to check</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="filePath"/> is set to null</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is set to empty or whitespace only characters</exception>
        /// <exception cref="VaultSystemCheckException">Thrown when there is not enough free space on drive</exception>
        public void CheckFreeSpace(NormalizedPath filePath);
        /// <summary>
        /// Calculates number of chunks that can be encrypted and written to disk in parrarel at the same time based on processor threads and available RAM memory
        /// </summary>
        /// <param name="chunkSizeInMB">Maximum size of each chunk</param>
        /// <returns>Lowest number between processor threads and maximum amount of chunks fitting in RAM at the same time, returned value is always higher or equal to 1</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="chunkSizeInMB"/> is set to zero</exception>
        public int CalculateConcurrency(ushort chunkSizeInMB);
    }


    public class SystemService : ISystemService
    {
        private IVaultSession _session => VaultSession.CurrentSession;

        public void CheckFreeSpace(NormalizedPath filePath)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(filePath);

            long availableBytes = new DriveInfo(Path.GetPathRoot(_session.VAULTPATH)!).AvailableFreeSpace;
            if (availableBytes < (GetTotalBytes(filePath) * 1.05))
            {
                throw new VaultSystemCheckException(VaultException.ErrorReason.NoFreeSpace);
            }
        }

        private long CheckFreeRamSpace()
        {
            return (GC.GetGCMemoryInfo().HighMemoryLoadThresholdBytes - GC.GetGCMemoryInfo().MemoryLoadBytes);
        }

        private long GetTotalBytes(NormalizedPath filePath)
        {
            ArgumentNullException.ThrowIfNull(filePath);
            if (!File.Exists(filePath)) throw new ArgumentException($"Cant find the file at {filePath}");

            return new FileInfo(filePath).Length;
        }

        public int CalculateConcurrency(ushort chunkSizeInMB)
        {
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);

            int maxConcurrentChunksInRam = (int)(CheckFreeRamSpace() / ((long)chunkSizeInMB * 1024 * 1024));
            int concurrencyToUse = Math.Min(Environment.ProcessorCount, maxConcurrentChunksInRam);
            return Math.Max(1, concurrencyToUse); //Ensuring returned value is 1 or higher
        }
    }
    

}
