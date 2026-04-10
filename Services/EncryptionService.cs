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
            if (new FileInfo(filePath).Length == 0) throw new VaultException(VaultException.ErrorContext.Encrypt, VaultException.ErrorReason.EmptyFile);
            ArgumentNullException.ThrowIfNull(context);

            _systemService.CheckFreeSpace(filePath);

            FileInfo fileInfo = new FileInfo(filePath);
            using (EncryptionOptions.FileEncryptionOptions options = _encryptionOptionsService.PrepareEncryptionOptions(fileInfo, algorithm, chunkSizeInMB))
            {
                var provider = algorithm.Provider();
                ulong totalChunks = options.ChunkInformation != null ? options.ChunkInformation!.TotalChunks : 1;
                int concurrentChunkCount = _systemService.CalculateConcurrency(options.IsChunked, chunkSizeInMB);
                await using FileStream vaultFS = new FileStream(_session.VAULTPATH, FileMode.Open, FileAccess.ReadWrite);
                await using FileStream fileFS = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                _session.VAULT_READER.AddAndSaveMetadataOffsets(vaultFS, vaultFS.Seek(0, SeekOrigin.End));

                using (SecureBuffer.SecureLargeBuffer paddedFileOptions = _encryptionOptionsService.PadAndEncryptFileEncryptionOptions(options))
                {
                    //Seek to the end of file to make sure its saved at the end and not after metadata data
                    vaultFS.Seek(0, SeekOrigin.End);
                    vaultFS.Write(paddedFileOptions.AsSpan);
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
            SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer((int)Math.Min((chunkSizeInMB * 1024 * 1024), fileFS.Length));
            try
            {
                //Object created to stop multiple threads for trying to write into vault file
                object writeLock = new object();
                while (chunkIndex < totalChunks)
                {
                    context.CancellationToken.ThrowIfCancellationRequested();

                    int bytesRead = await fileFS.ReadAsync(buffer.AsMemory);
                    if (bytesRead == 0) throw new VaultException(VaultException.ErrorContext.Encrypt, VaultException.ErrorReason.EndOfFile);

                    //Creating a copy of buffer to avoid race conditions
                    SecureBuffer.SecureLargeBuffer chunkCopy = new SecureBuffer.SecureLargeBuffer(bytesRead);
                    buffer.AsSpan[..bytesRead].CopyTo(chunkCopy.AsSpan);

                    ulong currentIndex = chunkIndex++;

                    if (tasks.Any(task => task.IsFaulted)) throw new VaultException(VaultException.ErrorContext.Encrypt, VaultException.ErrorReason.TaskFaulted);
                    if (tasks.Count >= concurrentChunkCount)
                    {
                        await Task.WhenAny(tasks);
                        tasks.RemoveAll(task => task.IsCompleted);
                    }

                    tasks.Add(Task.Run(() =>
                    {
                        context.CancellationToken.ThrowIfCancellationRequested();
                        SecureBuffer.SecureLargeBuffer encryptedChunk = null!;
                        try
                        {
                            encryptedChunk = provider.EncryptionAlgorithm.EncryptBytes(chunkCopy.AsSpan, _session.KEY.AsSpan[..provider.KeySize]);
                            results.TryAdd(currentIndex, encryptedChunk);
                            _fileService.WriteReadyChunk(results, ref nextToWrite, currentIndex, vaultFS, writeLock);
                        }
                        catch (Exception)
                        {
                            //Encrypted chunk usually gets cleaned in IFileService.WriteReadyChunk after writing, clean here if it throws
                            encryptedChunk?.Dispose();
                            throw;
                        }
                        finally
                        {
                            chunkCopy.Dispose();
                        }
                        
                        //Reporting current index + 1 because currentIndex is zero based while user gets to see 1 based indexing
                        context.Progress.Report(new ProgressStatus(currentIndex + 1, totalChunks));
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
