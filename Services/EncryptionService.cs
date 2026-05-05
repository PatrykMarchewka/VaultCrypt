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
    public interface IEncryptionService
    {
        /// <summary>
        /// Reads data from <paramref name="filePath"/>, encrypts it and saves in vault
        /// </summary>
        /// <param name="algorithm">Algorithm to encrypt data with</param>
        /// <param name="chunkSizeInMB">Maximum size of each chunk in megabytes, if file size is lower than chunk size then it gets encrypted in one singular chunk</param>
        /// <param name="filePath">Path to file to encrypt</param>
        /// <param name="context">Context to display progression</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="algorithm"/>, <paramref name="filePath"/> or <paramref name="context"/> are set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="chunkSizeInMB"/> value is set to zero</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is set to empty or whitespace only characters</exception>
        /// <exception cref="VaultException">Thrown when trying to encrypt empty file</exception>
        public Task Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, ushort chunkSizeInMB, NormalizedPath filePath, ProgressionContext context);
    }

    public class EncryptionService : IEncryptionService
    {
        private readonly IFileService _fileService;
        private readonly IEncryptionOptionsService _encryptionOptionsService;
        private readonly IVaultSession _session;
        private readonly ISystemService _systemService;

        public EncryptionService(IFileService fileService, IEncryptionOptionsService encryptionOptionsService, IVaultSession session, ISystemService systemService)
        {
            this._fileService = fileService;
            this._encryptionOptionsService = encryptionOptionsService;
            this._session = session;
            this._systemService = systemService;
        }

        public async Task Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, ushort chunkSizeInMB, NormalizedPath filePath, ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(algorithm);
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(filePath);
            long fileLength = await RetryHelper.TryUntilSuccessAsync(
                tryAction: () => new FileInfo(filePath).Length,
                catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed));
            if (fileLength == 0) throw new VaultException(VaultException.ErrorContext.Encrypt, VaultException.ErrorReason.EmptyFile);
            ArgumentNullException.ThrowIfNull(context);

            _systemService.CheckFreeSpace(filePath);

            FileInfo fileInfo = new FileInfo(filePath);
            using (EncryptionOptions.FileEncryptionOptions options = _encryptionOptionsService.PrepareEncryptionOptions(fileInfo, algorithm, chunkSizeInMB))
            {
                var provider = algorithm.Provider();
                ulong totalChunks = options.ChunkInformation != null ? options.ChunkInformation!.TotalChunks : 1;
                int concurrentChunkCount = _systemService.CalculateConcurrency(options.IsChunked, chunkSizeInMB);

                await using FileStream vaultFS = await RetryHelper.TryUntilSuccessAsync(
                    tryAction: () => new FileStream(_session.VAULTPATH, FileMode.Open, FileAccess.ReadWrite),
                    catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.CreatingStreamFailed));

                await using FileStream fileFS = await RetryHelper.TryUntilSuccessAsync(
                    tryAction: () => new FileStream(filePath, FileMode.Open, FileAccess.Read),
                    catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.CreatingStreamFailed));

                //First action is saving metadata
                context.SetTotal(1 + totalChunks);

                await RetryHelper.TryUntilSuccessAsync(
                    tryAction: () => _session.VAULT_READER.AddAndSaveMetadataOffsets(vaultFS, vaultFS.Seek(0, SeekOrigin.End)),
                    catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                context.Increment();

                using (SecureBuffer.SecureLargeBuffer paddedFileOptions = _encryptionOptionsService.PadAndEncryptFileEncryptionOptions(options))
                {
                    //Seek to the end of file to make sure its saved at the end and not after metadata data
                    //START HERE, why is this disposed???
                    await RetryHelper.TryUntilSuccessAsync(
                        tryAction: () => { vaultFS.Seek(0, SeekOrigin.End); vaultFS.Write(paddedFileOptions.AsSpan); },
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                }
                
                await EncryptChunks(fileFS, vaultFS, totalChunks, concurrentChunkCount, chunkSizeInMB, provider, context);
            }
        }

        private async Task EncryptChunks(Stream fileFS, Stream vaultFS, ulong totalChunks, int concurrentChunkCount, ushort chunkSizeInMB, EncryptionAlgorithm.IEncryptionAlgorithmProvider provider, ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(fileFS);
            ArgumentNullException.ThrowIfNull(vaultFS);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(totalChunks);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(concurrentChunkCount);
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);
            if(_session.KEY.AsSpan.IsEmpty) throw new InvalidOperationException("Provided empty key");
            ArgumentNullException.ThrowIfNull(context);

            var tasks = new List<Task>();
            var results = new ConcurrentDictionary<ulong, SecureBuffer.SecureLargeBuffer>();
            ulong nextToWrite = 0;
            ulong chunkIndex = 0;

            long originalFileSize = await RetryHelper.TryUntilSuccessAsync(
                tryAction: () => fileFS.Length,
                catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed));
            int bufferSize = (checked((int)Math.Min(chunkSizeInMB * 1024 * 1024, originalFileSize)));
            SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(bufferSize);
            try
            {
                //Object created to stop multiple threads for trying to write into vault file
                object writeLock = new object();
                while (chunkIndex < totalChunks)
                {
                    context.CancellationToken.ThrowIfCancellationRequested();
                    int bytesRead = 0;
                    ulong currentIndex = chunkIndex++;
                    try
                    {
                        bytesRead = await RetryHelper.TryUntilSuccessAsync(
                        tryAction: async () => await fileFS.ReadAsync(buffer.AsMemory),
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed));
                    }
                    catch (Exception)
                    {
                        //Exception intentionally ignored
                    }

                    if(bytesRead == 0)
                    {
                        //Failed to read from stream or unexpected end of stream reached, waiting for all tasks to finish in order to encrypt as much as we can
                        await Task.WhenAll(tasks);
                        context.ReportPermStatus(ProgressFailure.ProgressPermFailure.UnexpectedEndOfStream, $"Cant read past chunk #{currentIndex}");
                        context.ForceFinish();
                        return;
                    }
                    SecureBuffer.SecureLargeBuffer currentChunk = new SecureBuffer.SecureLargeBuffer(bytesRead);
                    buffer.AsSpan[..bytesRead].CopyTo(currentChunk.AsSpan);

                    if (tasks.Any(task => task.IsFaulted)) throw new VaultException(VaultException.ErrorContext.Encrypt, VaultException.ErrorReason.TaskFaulted);
                    if (tasks.Count >= concurrentChunkCount)
                    {
                        await Task.WhenAny(tasks);
                        tasks.RemoveAll(task => task.IsCompleted);
                    }

                    tasks.Add(Task.Run(async () =>
                    {
                        context.CancellationToken.ThrowIfCancellationRequested();
                        SecureBuffer.SecureLargeBuffer encryptedChunk = null!;
                        try
                        {
                            encryptedChunk = provider.EncryptionAlgorithm.EncryptBytes(currentChunk.AsSpan, _session.KEY.AsSpan[..provider.KeySize]);
                            results.TryAdd(currentIndex, encryptedChunk);
                            await RetryHelper.TryUntilSuccessAsync(
                                tryAction: () => _fileService.WriteReadyChunk(results, ref nextToWrite, currentIndex, vaultFS, writeLock),
                                catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                        }
                        catch (Exception)
                        {
                            //Encrypted chunk usually gets cleaned in IFileService.WriteReadyChunk after writing, clean here if it throws
                            encryptedChunk?.Dispose();
                            throw;
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
