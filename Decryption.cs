using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt
{
    internal class Decryption
    {
        internal static async Task Decrypt(long metadataOffset, NormalizedPath folderPath, ProgressionContext context)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(metadataOffset);
            ArgumentNullException.ThrowIfNull(folderPath);
            ArgumentNullException.ThrowIfNull(context);

            await using FileStream vaultFS = new FileStream(VaultSession.CurrentSession.VAULTPATH!, FileMode.Open, FileAccess.Read);
            EncryptionOptions.FileEncryptionOptions encryptionOptions = EncryptionOptions.GetDecryptedFileEncryptionOptions(vaultFS, metadataOffset);

            try
            {
                NormalizedPath filePath = NormalizedPath.From(folderPath + "\\" + Encoding.UTF8.GetString(encryptionOptions.fileName))!;
                var encryptionProtocol = EncryptionOptions.GetEncryptionProtocolInfo[encryptionOptions.encryptionProtocol];
                ReadOnlyMemory<byte> key = PasswordHelper.GetSlicedKey(encryptionProtocol.keySize);
                var decryptMethod = encryptionProtocol.decryptMethod;
                if (!encryptionOptions.chunked)
                {
                    byte[]? decrypted = null;
                    try
                    {
                        decrypted = DecryptInOneChunk(vaultFS, encryptionOptions.fileSize, key, decryptMethod);
                        File.WriteAllBytes(filePath!, decrypted);
                        context.Progress.Report(new ProgressStatus(1, 1));
                    }
                    finally
                    {
                        if (decrypted is not null) CryptographicOperations.ZeroMemory(decrypted);
                    }
                }
                else
                {
                    await using FileStream fileFS = new FileStream(filePath!, FileMode.Create);
                    await DecryptInMultipleChunks(vaultFS, fileFS, encryptionOptions.chunkInformation!.Value, encryptionProtocol.encryptionDataSize, key, decryptMethod, context);
                }
            }
            finally
            {
                EncryptionOptions.WipeFileEncryptionOptions(ref encryptionOptions);
            }
        }

        static byte[] DecryptInOneChunk(Stream vaultFS, ulong fileSize, ReadOnlyMemory<byte> key, Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, byte[]> decryptMethod)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(fileSize);
            if (key.Length == 0) throw new VaultException("Failed to decrypt data, provided key was empty");
            ArgumentNullException.ThrowIfNull(decryptMethod);

            byte[] buffer = new byte[fileSize];
            try
            {
                vaultFS.ReadExactly(buffer);
                return decryptMethod(buffer, key);
            }
            catch(EndOfStreamException ex)
            {
                throw VaultException.EndOfFileException(ex);
            }
            catch(Exception ex)
            {
                throw new VaultException("Couldn't decrypt single chunked file", ex);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="vaultFS"></param>
        /// <param name="fileFS"></param>
        /// <param name="chunkInformation"></param>
        /// <param name="extraData"></param>
        /// <param name="key"></param>
        /// <param name="decryptMethod"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        static async Task DecryptInMultipleChunks(Stream vaultFS, Stream fileFS, EncryptionOptions.ChunkInformation chunkInformation, short extraData, ReadOnlyMemory<byte> key, Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, byte[]> decryptMethod, ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);
            ArgumentNullException.ThrowIfNull(fileFS);
            ArgumentOutOfRangeException.ThrowIfNegative(extraData);
            if (key.Length == 0) throw new VaultException("Failed to decrypt data, provided key was empty");
            ArgumentNullException.ThrowIfNull(decryptMethod);
            ArgumentNullException.ThrowIfNull(context);

            var tasks = new List<Task>();
            var results = new ConcurrentDictionary<int, byte[]>();
            int concurrentChunkCount = FileHelper.CalculateConcurrency(true, chunkInformation.chunkSize);
            int nextToWrite = 0;
            int chunkIndex = 0;
            byte[] buffer = new byte[extraData + (chunkInformation.chunkSize * 1024 * 1024)];
            try
            {
                object writeLock = new object();
                while (chunkIndex < chunkInformation.totalChunks)
                {
                    context.CancellationToken.ThrowIfCancellationRequested();
                    int bytesRead = 0;
                    int currentIndex = chunkIndex++;
                    byte[] currentChunk = null!;
                    try
                    {
                        if (chunkIndex == chunkInformation.totalChunks)
                        {
                            //read the extraData + chunkInformation.finalChunkSize
                            bytesRead = await vaultFS.ReadAsync(buffer, 0, checked((int)(extraData + chunkInformation.finalChunkSize)));
                        }
                        else
                        {
                            //read the extra data + normal amount
                            bytesRead = await vaultFS.ReadAsync(buffer, 0, buffer.Length);
                        }

                        //End of file throw
                        if (bytesRead == 0) throw VaultException.EndOfFileException();

                        currentChunk = new byte[bytesRead];
                        Buffer.BlockCopy(buffer, 0, currentChunk, 0, bytesRead);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(buffer);
                    }

                    

                    if (tasks.Count >= concurrentChunkCount)
                    {
                        var finished = await Task.WhenAny(tasks);
                        tasks.Remove(finished);
                    }

                    tasks.Add(Task.Run(() =>
                    {
                        context.CancellationToken.ThrowIfCancellationRequested();
                        byte[] decryptedChunk = null!;
                        try
                        {
                            decryptedChunk = decryptMethod(currentChunk, key);
                            results.TryAdd(currentIndex, decryptedChunk);
                        }
                        finally
                        {
                            if (decryptedChunk is not null) CryptographicOperations.ZeroMemory(decryptedChunk);
                            if(currentChunk is not null) CryptographicOperations.ZeroMemory(currentChunk);
                        }
                        FileHelper.WriteReadyChunk(results, ref nextToWrite, currentIndex, fileFS, writeLock);
                        //Reporting current index + 1 because currentIndex is zero based while user gets to see 1 based indexing
                        context.Progress.Report(new ProgressStatus(currentIndex + 1, chunkInformation.totalChunks));
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







        internal static class AesGcmDecryption
        {
            /// <summary>
            /// 
            /// </summary>
            /// <param name="data"></param>
            /// <param name="key"></param>
            /// <returns></returns>
            /// <exception cref="VaultException">Thrown when decryption failed</exception>
            internal static byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to decrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to decrypt bytes, provided key was empty");

                ReadOnlySpan<byte> iv = data.Slice(0,12);
                ReadOnlySpan<byte> tag = data.Slice(12, 16);
                ReadOnlySpan<byte> encryptedData = data.Slice(28);

                byte[] decrypted = new byte[encryptedData.Length];
                try
                {
                    using AesGcm aesGcm = new AesGcm(key, 16);
                    aesGcm.Decrypt(iv, encryptedData, tag, decrypted);
                    return decrypted;

                }
                catch (Exception ex)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw VaultException.DecryptionFailed(ex);
                }
            }
        }
    }
}
