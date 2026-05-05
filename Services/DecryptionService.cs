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
    public interface IDecryptionService
    {
        /// <summary>
        /// Reads data from vault at <paramref name="metadataOffset"/>, decrypts it and saves at <paramref name="filePath"/>
        /// </summary>
        /// <param name="metadataOffset">Offset to <see cref="EncryptionOptions.FileEncryptionOptions"/></param>
        /// <param name="filePath">Path to file after decrypting, if file already exists it will be overwritten </param>
        /// <param name="context">Context to display progression</param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="metadataOffset"/> points to vault metadata or is set to negative value</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="filePath"/> or <paramref name="context"/> are set to null</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is set to empty or whitespace only characters</exception>
        public Task Decrypt(long metadataOffset, NormalizedPath filePath, ProgressionContext context);
    }

    public class DecryptionService : IDecryptionService
    {
        private readonly IFileService _fileService;
        private readonly IEncryptionOptionsService _encryptionOptionsService;
        private readonly IVaultSession _session;
        private readonly ISystemService _systemService;

        public DecryptionService(IFileService fileService, IEncryptionOptionsService encryptionOptionsService, IVaultSession session, ISystemService systemService)
        {
            this._fileService = fileService;
            this._encryptionOptionsService = encryptionOptionsService;
            this._session = session;
            this._systemService = systemService;
        }


        public async Task Decrypt(long metadataOffset, NormalizedPath filePath, ProgressionContext context)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(metadataOffset, _session.VAULT_READER.MetadataOffsetsSize);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(filePath);
            ArgumentNullException.ThrowIfNull(context);

            await using FileStream vaultFS = await RetryHelper.TryUntilSuccessAsync(
                tryAction: () => new FileStream(_session.VAULTPATH, FileMode.Open, FileAccess.Read),
                catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.CreatingStreamFailed));
            using EncryptionOptions.FileEncryptionOptions encryptionOptions = await RetryHelper.TryUntilSuccessAsync(
                tryAction: () => _encryptionOptionsService.GetDecryptedFileEncryptionOptions(vaultFS, metadataOffset),
                catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed),
                shouldRetry: ex => ex is IOException);
            var encryptionAlgorithmProvider = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[encryptionOptions.EncryptionAlgorithm].Provider();
            await using FileStream fileFS = await RetryHelper.TryUntilSuccessAsync(
                tryAction: () => new FileStream(filePath, FileMode.Create),
                catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.CreatingStreamFailed));
            if (!encryptionOptions.IsChunked)
            {
                try
                {
                    using (SecureBuffer.SecureLargeBuffer decrypted = await RetryHelper.TryUntilSuccessAsync(
                        tryAction: () => DecryptInOneChunk(vaultFS, checked((int)encryptionOptions.FileSize), _session.GetSlicedKey(encryptionAlgorithmProvider.KeySize), encryptionAlgorithmProvider.EncryptionAlgorithm),
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed),
                        shouldRetry: ex => ex is IOException))
                    {
                        await RetryHelper.TryUntilSuccessAsync(
                            tryAction: () => fileFS.Write(decrypted.AsSpan),
                            catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                    }
                }
                catch (Exception)
                {
                    context.ReportPermStatus(ProgressFailure.ProgressPermFailure.ChunkDecryptFailed, 1);
                }
                context.Increment();
            }
            else
            {
                context.SetTotal(encryptionOptions.ChunkInformation!.TotalChunks);
                await DecryptInMultipleChunks(vaultFS, fileFS, encryptionOptions.ChunkInformation!, encryptionAlgorithmProvider.EncryptionAlgorithm.ExtraEncryptionDataSize, encryptionAlgorithmProvider, context);
            }
        }

        private SecureBuffer.SecureLargeBuffer DecryptInOneChunk(Stream vaultFS, int fileSize, ReadOnlySpan<byte> key, EncryptionAlgorithm.IEncryptionAlgorithm encryptionAlgorithm)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(fileSize);
            if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));
            ArgumentNullException.ThrowIfNull(encryptionAlgorithm);

            using (SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(fileSize))
            {
                vaultFS.ReadExactly(buffer.AsSpan);
                return encryptionAlgorithm.DecryptBytes(buffer.AsSpan, key);
            }
        }

        private async Task DecryptInMultipleChunks(Stream vaultFS, Stream fileFS, EncryptionOptions.ChunkInformation chunkInformation, short extraData, EncryptionAlgorithm.IEncryptionAlgorithmProvider provider, ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);
            ArgumentNullException.ThrowIfNull(fileFS);
            ArgumentOutOfRangeException.ThrowIfNegative(extraData);
            if (_session.KEY.AsSpan.IsEmpty) throw new ArgumentException("Provided empty key", nameof(_session.KEY));
            ArgumentNullException.ThrowIfNull(provider);
            ArgumentNullException.ThrowIfNull(context);

            var tasks = new List<Task>();
            var results = new ConcurrentDictionary<ulong, SecureBuffer.SecureLargeBuffer>();
            int concurrentChunkCount = _systemService.CalculateConcurrency(true, chunkInformation.ChunkSize);
            ulong nextToWrite = 0;
            ulong chunkIndex = 0;
            SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(extraData + (chunkInformation.ChunkSize * 1024 * 1024));
            try
            {
                object writeLock = new object();
                while (chunkIndex < chunkInformation.TotalChunks)
                {
                    context.CancellationToken.ThrowIfCancellationRequested();
                    int bytesRead = 0;
                    ulong currentIndex = chunkIndex++;

                    
                    try
                    {
                        bytesRead = await RetryHelper.TryUntilSuccessAsync(
                        tryAction: async () => { return await vaultFS.ReadAsync(buffer.AsMemory); },
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed));
                    }
                    catch (Exception)
                    {
                        //Exception intentionally ignored
                    }

                    if(bytesRead == 0)
                    {
                        //Failed to read from stream or unexpected end of stream reached, waiting for all tasks to finish in order to decrypt as much as we can
                        await Task.WhenAll(tasks);
                        context.ReportPermStatus(ProgressFailure.ProgressPermFailure.UnexpectedEndOfStream, $"Cant read past chunk #{currentIndex}");
                        context.ForceFinish();
                        return;
                    }

                    SecureBuffer.SecureLargeBuffer currentChunk = new SecureBuffer.SecureLargeBuffer(bytesRead);
                    buffer.AsSpan[..bytesRead].CopyTo(currentChunk.AsSpan);

                    if (tasks.Any(task => task.IsFaulted)) throw new VaultException(VaultException.ErrorContext.Decrypt, VaultException.ErrorReason.TaskFaulted);
                    if (tasks.Count >= concurrentChunkCount)
                    {
                        await Task.WhenAny(tasks);
                        tasks.RemoveAll(task => task.IsCompleted);
                    }

                    tasks.Add(Task.Run(async () =>
                    {
                        context.CancellationToken.ThrowIfCancellationRequested();
                        SecureBuffer.SecureLargeBuffer decryptedChunk = null!;
                        try
                        {
                            decryptedChunk = provider.EncryptionAlgorithm.DecryptBytes(currentChunk.AsSpan, _session.KEY.AsSpan[..provider.KeySize]);
                            results.TryAdd(currentIndex, decryptedChunk);

                            await RetryHelper.TryUntilSuccessAsync(
                                tryAction: () => _fileService.WriteReadyChunk(results, ref nextToWrite, currentIndex, fileFS, writeLock),
                                catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                        }
                        catch (Exception)
                        {
                            //Decrypted chunk usually gets cleaned in IFileService.WriteReadyChunk after writing, clean here if it throws
                            decryptedChunk?.Dispose();
                            context.ReportPermStatus(ProgressFailure.ProgressPermFailure.ChunkDecryptFailed, currentIndex);
                        }
                        finally
                        {
                            currentChunk.Dispose();
                        }
                        context.Increment();
                    }));
                }
                await Task.WhenAll(tasks);
            }
            finally
            {
                buffer.Dispose();
                foreach (var result in results.Values)
                {
                    result.Dispose();
                }
                results.Clear();
            }
        }
    }
}
