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
        internal static void CreateVault(NormalizedPath folderPath, string vaultName, byte[] password, int iterations)
        {
            Span<byte> buffer = stackalloc byte[1 + 32 + sizeof(uint)]; //1 byte for version + 32 byte salt + 4 bytes for iterations number
            buffer[0] = 0;
            byte[] salt = PasswordHelper.GenerateRandomSalt();
            salt.AsSpan().CopyTo(buffer.Slice(1, 32));
            BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(1 + 32, 4), iterations);

            //Set vault session parameters
            VaultSession.VERSION = 0;
            VaultSession.VAULTPATH = NormalizedPath.From(NormalizedPath.Normalize(folderPath + vaultName + ".vlt"));
            VaultSession.SALT = salt;
            VaultSession.ITERATIONS = iterations;
            VaultSession.KEY = PasswordHelper.DeriveKey(password);


            byte[] metadataBuffer = new byte[sizeof(ushort) + 4096];
            byte[] encryptedMetadata = VaultRegistry.GetVaultReader(VaultSession.VERSION).VaultEncryption(metadataBuffer);

            using (var fs = File.Create(folderPath + "\\" + vaultName + ".vlt"))
            {
                fs.Write(buffer);
                fs.Write(encryptedMetadata);
            }
        }

        /// <summary>
        /// Checks whether there is enough free space to perform operation
        /// </summary>
        /// <param name="path">Path of the file to check</param>
        /// <exception cref="Exception">There is not enough free space on the disk with the vault or file can't be located</exception>
        internal static void CheckFreeSpace(NormalizedPath path)
        {
            long availableBytes = new DriveInfo(Path.GetPathRoot(VaultSession.VAULTPATH)).AvailableFreeSpace;

            if (availableBytes < (GetTotalBytes(path) * 1.05))
            {
                throw new Exception("Not enough free space");
            }
        }

        internal static long CheckFreeRamSpace()
        {
            return GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        }

        internal static long GetTotalBytes(NormalizedPath path)
        {
            if (File.Exists(path))
            {
                return new FileInfo(path).Length;

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

        internal static bool WriteSmallFile()
        {
            return WriteSmallFile(VaultSession.VAULTPATH);
        }

        internal static bool WriteSmallFile(NormalizedPath folderPath)
        {
            string path = folderPath + "vault.tmp";
            try
            {
                
                byte[] data = new byte[1024];
                RandomNumberGenerator.Fill(data);

                File.WriteAllBytes(path, data);

                byte[] returned = File.ReadAllBytes(path);

                if (data.Length != returned.Length)
                {
                    return false;
                }

                for (int i = 0; i < data.Length; i++)
                {
                    if (data[i] != returned[i])
                    {
                        return false;
                    }
                }

                return true;
            }
            catch
            {
                throw new Exception("Cant save file to disk");
            }
            finally
            {
                DeleteSmallFile(path);
            }
        }

        private static void DeleteSmallFile(string filePath)
        {
            try
            {
                File.Delete(filePath);
            }
            catch
            {
                throw new Exception($"Cannot delete: {filePath}");
            }
        }

        internal static void WriteFile(NormalizedPath filePath, byte[] data)
        {
            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Create))
                {
                    fs.Write(data, 0, data.Length);
                }
            }
            catch
            {
                throw new Exception("Cant save file to disk");
            }
        }

        internal static void WriteFile(string filePath, byte[] data)
        {
            WriteFile(NormalizedPath.From(filePath), data);
        }

        internal static void WriteReadyChunk(ConcurrentDictionary<int, byte[]> results, ref int nextToWrite, Stream fileFS, object lockObject)
        {
            lock (lockObject)
            {
                while (results.TryRemove(nextToWrite, out var ready))
                {
                    fileFS.Write(ready, 0, ready.Length);
                    CryptographicOperations.ZeroMemory(ready);
                    nextToWrite++;
                }
            }
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

        public static implicit operator string(NormalizedPath path) => path.Value;


    }

}
