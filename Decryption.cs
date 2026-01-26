using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class Decryption
    {
        internal static async Task Decrypt(long metadataOffset, NormalizedPath folderPath, VaultHelper.ProgressionContext context)
        {
            await using FileStream vaultFS = new FileStream(VaultSession.VAULTPATH, FileMode.Open, FileAccess.Read);
            EncryptionOptions.FileEncryptionOptions encryptionOptions = EncryptionOptions.GetDecryptedFileEncryptionOptions(vaultFS, metadataOffset);

            NormalizedPath filePath = NormalizedPath.From(folderPath + "\\" + Encoding.UTF8.GetString(encryptionOptions.fileName));
            var encryptionProtocol = EncryptionOptions.GetEncryptionProtocolInfo[encryptionOptions.encryptionProtocol];
            byte[] key = PasswordHelper.GetSlicedKey(encryptionProtocol.keySize);

            var decryptMethod = encryptionProtocol.decryptMethod;
            if (!encryptionOptions.chunked)
            {
                byte[] decrypted = DecryptInOneChunk(vaultFS, encryptionOptions.fileSize, key, decryptMethod);
                context.CancellationToken.ThrowIfCancellationRequested();
                File.WriteAllBytes(filePath, decrypted);
                context.Progress.Report(new VaultHelper.ProgressStatus(1, 1));
                CryptographicOperations.ZeroMemory(decrypted);
            }
            else
            {
                await using FileStream fileFS = new FileStream(filePath, FileMode.Create);
                await DecryptInMultipleChunks(vaultFS, fileFS, encryptionOptions.chunkInformation!.Value, encryptionProtocol.encryptionDataSize, key, decryptMethod, context);
            }
            CryptographicOperations.ZeroMemory(key);
            EncryptionOptions.WipeFileEncryptionOptions(ref encryptionOptions);
        }

        static byte[] DecryptInOneChunk(Stream vaultFS, ulong fileSize, byte[] key, Func<byte[], byte[], byte[]> decryptMethod)
        {
            byte[] buffer = new byte[fileSize];
            vaultFS.ReadExactly(buffer);
            return decryptMethod(buffer, key);
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
        static async Task DecryptInMultipleChunks(Stream vaultFS, Stream fileFS, EncryptionOptions.ChunkInformation chunkInformation, short extraData, byte[] key, Func<byte[], byte[], byte[]> decryptMethod, VaultHelper.ProgressionContext context)
        {
            var tasks = new List<Task>();
            var results = new ConcurrentDictionary<int, byte[]>();
            int concurrentChunkCount = FileHelper.CalculateConcurrency(true, chunkInformation.chunkSize);
            int nextToWrite = 0;
            int chunkIndex = 0;
            byte[] buffer = new byte[extraData + (chunkInformation.chunkSize * 1024 * 1024)];

            object writeLock = new object();
            while (chunkIndex < chunkInformation.totalChunks)
            {
                int bytesRead = 0;
                int currentIndex = chunkIndex++;
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
                if (bytesRead == 0) throw new Exception("EOF");

                byte[] currentChunk = new byte[bytesRead];
                Buffer.BlockCopy(buffer, 0, currentChunk, 0, bytesRead);

                if (tasks.Count >= concurrentChunkCount)
                {
                    var finished = await Task.WhenAny(tasks);
                    tasks.Remove(finished);
                }

                tasks.Add(Task.Run(() =>
                {
                    context.CancellationToken.ThrowIfCancellationRequested();

                    byte[] decryptedChunk = decryptMethod(currentChunk, key);
                    results.TryAdd(currentIndex, decryptedChunk);
                    FileHelper.WriteReadyChunk(results, ref nextToWrite, currentIndex, fileFS, writeLock);
                    //Reporting current index + 1 because currentIndex is zero based while user gets to see 1 based indexing
                    context.Progress.Report(new VaultHelper.ProgressStatus(currentIndex + 1, chunkInformation.totalChunks));
                    CryptographicOperations.ZeroMemory(decryptedChunk);
                }));
            }
            await Task.WhenAll(tasks);
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
