using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class FileHelper
    {




        /// <summary>
        /// Checks whether there is enough free space to perform operation
        /// </summary>
        /// <param name="filePath">Path of the file to check</param>
        /// <exception cref="Exception">There is not enough free space on the disk with the vault or file can't be located</exception>
        internal static void CheckFreeSpace(NormalizedPath filePath)
        {
            long availableBytes = new DriveInfo(Path.GetPathRoot(VaultSession.VAULTPATH)).AvailableFreeSpace;

            if (availableBytes < (GetTotalBytes(filePath) * 1.05))
            {
                throw new Exception("Not enough free space");
            }
        }

        internal static long CheckFreeRamSpace()
        {
            return (GC.GetGCMemoryInfo().HighMemoryLoadThresholdBytes - GC.GetGCMemoryInfo().MemoryLoadBytes);
        }

        private static long GetTotalBytes(NormalizedPath filePath)
        {
            if (File.Exists(filePath))
            {
                return new FileInfo(filePath).Length;

            }
            else
            {
                throw new Exception("Cant find the file");
            }
        }

        internal static int CalculateConcurrency(bool chunked, ushort chunkSizeInMB)
        {
            if (!chunked) return 1;
            int threadCount = Math.Max(1, Environment.ProcessorCount);
            int ramSpace = (int)(CheckFreeRamSpace() / (chunkSizeInMB * 1024 * 1024));
            return Math.Min(threadCount, ramSpace);
        }

        


        internal static void WriteReadyChunk(ConcurrentDictionary<int, byte[]> results, ref int nextToWrite, int currentIndex, Stream fileFS, object lockObject)
        {
            lock (lockObject)
            {
                byte[] ready;
                while (nextToWrite != currentIndex)
                {
                    Monitor.Wait(lockObject);
                }

                if (!results.TryRemove(nextToWrite, out ready!)) throw new Exception("Missing chunk");

                try
                {
                    fileFS.Write(ready, 0, ready.Length);
                }
                catch
                {
                    throw new Exception("Couldnt write to file");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ready);
                } 
                nextToWrite++;

                Monitor.PulseAll(lockObject);
            }
        }

        private static void ZeroOutPartOfFile(Stream stream, long offset, ulong length)
        {
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

        private static void CopyPartOfFile(Stream source, long offset, ulong length, Stream destination, long destinationOffset)
        {
            //8MB buffer
            byte[] buffer = new byte[8_388_608];

            source.Seek(offset, SeekOrigin.Begin);
            destination.Seek(destinationOffset, SeekOrigin.Begin);
            while (length > 0)
            {
                //Length is provided as ulong to support fileSizes above 2GB
                int chunkSize = (int)Math.Min(length, (ulong)buffer.Length);
                source.ReadExactly(buffer, 0, chunkSize);
                destination.Write(buffer, 0, chunkSize);
                length -= (ulong)chunkSize;
            }
        }

        internal static void TrimVault(VaultHelper.ProgressionContext context)
        {
            CheckFreeSpace(VaultSession.VAULTPATH);
            using FileStream vaultfs = new FileStream(VaultSession.VAULTPATH, FileMode.Open, FileAccess.Read);
            using FileStream newVaultfs = new FileStream(VaultSession.VAULTPATH + "_TRIMMED.vlt", FileMode.Create);

            var reader = VaultRegistry.GetVaultReader(VaultSession.VERSION);
            CopyPartOfFile(vaultfs, 0, (ulong)reader.HeaderSize, newVaultfs, newVaultfs.Seek(0, SeekOrigin.End));
            var fileList = VaultSession.ENCRYPTED_FILES.ToList();
            long[] newVaultOffsets = new long[fileList.Count];
            for (int i = 0; i < fileList.Count; i++)
            {
                context.CancellationToken.ThrowIfCancellationRequested();
                long currentOffset = fileList[i].Key;
                long nextOffset = long.MaxValue;
                if (i + 1 < fileList.Count)
                {
                    nextOffset = fileList[i + 1].Key;
                }

                EncryptionOptions.FileEncryptionOptions encryptionOptions = EncryptionOptions.GetDecryptedFileEncryptionOptions(vaultfs, currentOffset);
                ulong fileSize = encryptionOptions.fileSize;
                EncryptionOptions.WipeFileEncryptionOptions(ref encryptionOptions);
                //Calculating toread to allow copying of partially encrypted files
                ulong toread = Math.Min((ulong)(nextOffset - currentOffset), (ulong)reader.EncryptionOptionsSize + fileSize);
                newVaultOffsets[i] = newVaultfs.Seek(0, SeekOrigin.End);
                CopyPartOfFile(vaultfs, currentOffset, toread, newVaultfs, newVaultOffsets[i]);
                //Reporting current index + 1 because i is zero based while user gets to see 1 based indexing, total is filelList.Count + 1 because last action is saving new header
                context.Progress.Report(new VaultHelper.ProgressStatus(i + 1, fileList.Count + 1));
            }
            reader.SaveMetadataOffsets(newVaultfs, newVaultOffsets);
            context.Progress.Report(new VaultHelper.ProgressStatus(fileList.Count + 1, fileList.Count + 1));
        }

        internal static void DeleteFileFromVault(KeyValuePair<long, string> FileMetadataEntry, VaultHelper.ProgressionContext context)
        {
            using FileStream vaultFS = new FileStream(VaultSession.VAULTPATH, FileMode.Open, FileAccess.ReadWrite);
            EncryptionOptions.FileEncryptionOptions encryptionOptions = EncryptionOptions.GetDecryptedFileEncryptionOptions(vaultFS, FileMetadataEntry.Key);
            //If the file is at the end, just trim the entire file, otherwise zero out the block
            if (VaultSession.ENCRYPTED_FILES.Last().Equals(FileMetadataEntry))
            {
                vaultFS.SetLength(FileMetadataEntry.Key);
            }
            else
            {
                //Calculate length incase of partially written file
                var encryptionMetadataSize = VaultRegistry.GetVaultReader(VaultSession.VERSION).EncryptionOptionsSize;
                var fileList = VaultSession.ENCRYPTED_FILES.ToList();
                int currentKey = fileList.FindIndex(file => file.Key == FileMetadataEntry.Key);
                ulong length = Math.Min(encryptionOptions.fileSize + (ulong)encryptionMetadataSize, (ulong)(fileList[currentKey + 1].Key - fileList[currentKey].Key));
                ZeroOutPartOfFile(vaultFS, FileMetadataEntry.Key, length);
            }
            EncryptionOptions.WipeFileEncryptionOptions(ref encryptionOptions);
            VaultRegistry.GetVaultReader(VaultSession.VERSION).RemoveAndSaveMetadataOffsets(vaultFS, checked((ushort)VaultSession.ENCRYPTED_FILES.ToList().FindIndex(file => file.Equals(FileMetadataEntry))));
            context.Progress.Report(new VaultHelper.ProgressStatus(1, 1));
        }

    }
    internal class NormalizedPath
    {
        internal string Value { get; }
        private NormalizedPath(string path)
        {
            Value = Normalize(path);
        }
        private static string Normalize(string path)
        {
            return path.Length > 260 && !path.StartsWith(@"\\?\") ? @"\\?\" + path : path;
        }

        internal static NormalizedPath From(string input) => new NormalizedPath(input);

        public override string ToString()
        {
            return Value;
        }

        public static implicit operator string?(NormalizedPath? path) => path?.Value;


    }

}
