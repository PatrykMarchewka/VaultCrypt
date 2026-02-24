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

namespace VaultCrypt
{
    internal class SystemHelper
    {
        /// <summary>
        /// Checks whether there is enough free space to perform operation
        /// </summary>
        /// <param name="filePath">Path of the file to check</param>
        /// <exception cref="Exception">There is not enough free space on the disk with the vault or file can't be located</exception>
        internal static void CheckFreeSpace(NormalizedPath filePath)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            long availableBytes = new DriveInfo(Path.GetPathRoot(VaultSession.CurrentSession.VAULTPATH)!).AvailableFreeSpace;
            if (availableBytes < (GetTotalBytes(filePath) * 1.05))
            {
                throw new VaultException(VaultException.ErrorContext.SystemCheck, VaultException.ErrorReason.NoFreeSpace);
            }
        }

        private static long CheckFreeRamSpace()
        {
            return (GC.GetGCMemoryInfo().HighMemoryLoadThresholdBytes - GC.GetGCMemoryInfo().MemoryLoadBytes);
        }

        private static long GetTotalBytes(NormalizedPath filePath)
        {
            ArgumentNullException.ThrowIfNull(filePath);
            if (!File.Exists(filePath)) throw new ArgumentException($"Cant find the file at {filePath}");

            return new FileInfo(filePath!).Length;
        }

        internal static int CalculateConcurrency(bool chunked, ushort chunkSizeInMB)
        {
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);

            if (!chunked) return 1;
            int threadCount = Math.Max(1, Environment.ProcessorCount);
            int ramSpace = (int)(CheckFreeRamSpace() / (chunkSizeInMB * 1024 * 1024));
            return Math.Min(threadCount, ramSpace);
        }
    }
    

}
