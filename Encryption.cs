using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.IO.Packaging;
using System.Linq;
using System.Printing.IndexedProperties;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Documents;
using VaultCrypt.Exceptions;

namespace VaultCrypt
{
    internal class Encryption
    {

        internal static async Task Encrypt(EncryptionOptions.EncryptionProtocol protocol, ushort chunkSizeInMB, NormalizedPath filePath, ProgressionContext context)
        {
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);
            ArgumentNullException.ThrowIfNull(filePath);
            ArgumentNullException.ThrowIfNull(context);

            FileHelper.CheckFreeSpace(filePath);

            EncryptionOptions.FileEncryptionOptions options = default;
            try
            {
                FileInfo fileInfo = new FileInfo(filePath);
                options = EncryptionOptions.PrepareEncryptionOptions(fileInfo, protocol, chunkSizeInMB);
                int totalChunks = options.chunkInformation != null ? options.chunkInformation.Value.totalChunks : 1;
                int concurrentChunkCount = FileHelper.CalculateConcurrency(options.chunked, chunkSizeInMB);
                ReadOnlyMemory<byte> key = PasswordHelper.GetSlicedKey(protocol);
                await using FileStream vaultFS = new FileStream(VaultSession.CurrentSession.VAULTPATH, FileMode.Open, FileAccess.ReadWrite);
                await using FileStream fileFS = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                VaultSession.CurrentSession.VAULT_READER.AddAndSaveMetadataOffsets(vaultFS, vaultFS.Seek(0, SeekOrigin.End));

                byte[] paddedFileOptions = null!;
                try
                {
                    paddedFileOptions = EncryptionOptions.EncryptAndPadFileEncryptionOptions(ref options);
                    //Seek to the end of file to make sure its saved at the end and not after metadata data
                    vaultFS.Seek(0, SeekOrigin.End);
                    vaultFS.Write(paddedFileOptions);
                    
                }
                finally
                {
                    if(paddedFileOptions is not null) CryptographicOperations.ZeroMemory(paddedFileOptions);
                }
                await EncryptChunks(fileFS, vaultFS, totalChunks, concurrentChunkCount, chunkSizeInMB, protocol, key, context);
            }
            finally
            {
                EncryptionOptions.WipeFileEncryptionOptions(ref options);
            }
        }

        static async Task EncryptChunks(Stream fileFS, Stream vaultFS, int totalChunks, int concurrentChunkCount, ushort chunkSizeInMB, EncryptionOptions.EncryptionProtocol protocol, ReadOnlyMemory<byte> key, ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(fileFS);
            ArgumentNullException.ThrowIfNull(vaultFS);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(totalChunks);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(concurrentChunkCount);
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);
            if (key.Length == 0) throw new VaultException("Failed to encrypt chunk, provided empty key");
            ArgumentNullException.ThrowIfNull(context);

            var tasks = new List<Task>();
            var results = new ConcurrentDictionary<int, byte[]>();
            int nextToWrite = 0;
            int chunkIndex = 0;
            byte[] buffer = new byte[Math.Min((chunkSizeInMB * 1024 * 1024), fileFS.Length)];
            var encryptMethod = EncryptionOptions.GetEncryptionProtocolInfo[protocol].encryptMethod;

            try
            {
                //Object created to stop multiple threads for trying to write into vault file
                object writeLock = new object();
                while (chunkIndex < totalChunks)
                {
                    context.CancellationToken.ThrowIfCancellationRequested();
                    byte[] chunk = null!;
                    try
                    {
                        int bytesRead = await fileFS.ReadAsync(buffer);
                        chunk = new byte[bytesRead];
                        Buffer.BlockCopy(buffer, 0, chunk, 0, bytesRead);

                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(buffer);
                    }


                    int currentIndex = chunkIndex++;

                    if (tasks.Count >= concurrentChunkCount)
                    {
                        var finished = await Task.WhenAny(tasks);
                        tasks.Remove(finished);
                    }

                    tasks.Add(Task.Run(() =>
                    {
                        byte[] encrypted = null!;
                        try
                        {
                            encrypted = encryptMethod(chunk, key);
                            results.TryAdd(currentIndex, encrypted);
                        }
                        finally
                        {
                            if (chunk is not null) CryptographicOperations.ZeroMemory(chunk);
                            CryptographicOperations.ZeroMemory(encrypted);
                        }
                        FileHelper.WriteReadyChunk(results, ref nextToWrite, currentIndex, vaultFS, writeLock);
                        //Reporting current index + 1 because currentIndex is zero based while user gets to see 1 based indexing
                        context.Progress.Report(new ProgressStatus(currentIndex + 1, totalChunks));
                    }));
                }
                await Task.WhenAll(tasks);
            }
            finally
            {
                foreach (var result in results.Values)
                {
                    CryptographicOperations.ZeroMemory(result);
                }
                results.Clear();
            }
        }

        internal static class AesGcmEncryption
        {
            internal static byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to encrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to encrypt bytes, provided key was empty");

                byte[] iv = new byte[12];
                byte[] authentication = new byte[16];
                byte[] output = new byte[data.Length];
                byte[] encrypted = new byte[iv.Length + authentication.Length + output.Length];
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    using (AesGcm aesGcm = new AesGcm(key, 16))
                    {
                        aesGcm.Encrypt(iv, data, output, authentication);
                    }
                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    Buffer.BlockCopy(authentication, 0, encrypted, iv.Length, authentication.Length);
                    Buffer.BlockCopy(output, 0, encrypted, iv.Length + authentication.Length, output.Length);
                    return encrypted;
                }
                catch (Exception ex)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw VaultException.EncryptionFailed(ex);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(iv);
                    CryptographicOperations.ZeroMemory(authentication);
                    CryptographicOperations.ZeroMemory(output);
                }
            }
        }
    }
}
