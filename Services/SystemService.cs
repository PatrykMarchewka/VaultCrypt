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
        /// <exception cref="VaultException">Thrown when there is not enough free space on drive</exception>
        public void CheckFreeSpace(NormalizedPath filePath);
        /// <summary>
        /// Calculates number of chunks that can be encrypted and written to disk in parrarel at the same time based on processor threads and available RAM memory
        /// </summary>
        /// <param name="chunked">Dictates whether file is meant to be chunked</param>
        /// <param name="chunkSizeInMB">Maximum size of each chunk</param>
        /// <returns>Returns 1 if <paramref name="chunked"/> is set to false, otherwise 1 or higher number</returns>
        public int CalculateConcurrency(bool chunked, ushort chunkSizeInMB);
    }


    public class SystemService : ISystemService
    {
        private readonly IVaultSession _session;

        public SystemService(IVaultSession session)
        {
            this._session = session;
        }

        public void CheckFreeSpace(NormalizedPath filePath)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            long availableBytes = new DriveInfo(Path.GetPathRoot(_session.VAULTPATH)!).AvailableFreeSpace;
            if (availableBytes < (GetTotalBytes(filePath) * 1.05))
            {
                throw new VaultException(VaultException.ErrorContext.SystemCheck, VaultException.ErrorReason.NoFreeSpace);
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

            return new FileInfo(filePath!).Length;
        }

        public int CalculateConcurrency(bool chunked, ushort chunkSizeInMB)
        {
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);

            if (!chunked) return 1;
            //Cast to long to interpret the byte value as long and not an int, preventing int overflow for chunkSize >= 2048
            int ramSpace = (int)(CheckFreeRamSpace() / ((long)chunkSizeInMB * 1024 * 1024)) / 2; //Divided by 2 to account for HDDs as they cant read and write at the same time
            return Math.Max(1, Math.Min(Environment.ProcessorCount, ramSpace));
        }
    }
    

}
