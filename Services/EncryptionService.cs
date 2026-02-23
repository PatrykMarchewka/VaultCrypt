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
        Task Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, ushort chunkSizeInMB, NormalizedPath filePath, ProgressionContext context);
    }

    internal class EncryptionService : IEncryptionService
    {
        private readonly IFileService _fileService;
        private readonly IEncryptionOptionsService _encryptionOptionsService;
        private readonly IVaultSession _session;

        public EncryptionService(IFileService fileService, IEncryptionOptionsService encryptionOptionsService, IVaultSession session)
        {
            this._fileService = fileService;
            this._encryptionOptionsService = encryptionOptionsService;
            this._session = session;
        }

        public async Task Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, ushort chunkSizeInMB, NormalizedPath filePath, ProgressionContext context)
        {
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);
            ArgumentNullException.ThrowIfNull(filePath);
            ArgumentNullException.ThrowIfNull(context);

            SystemHelper.CheckFreeSpace(filePath);

            EncryptionOptions.FileEncryptionOptions options = null!;
            var provider = algorithm.provider();
            try
            {
                FileInfo fileInfo = new FileInfo(filePath!);
                options = _encryptionOptionsService.PrepareEncryptionOptions(fileInfo, algorithm, chunkSizeInMB);
                int totalChunks = options.ChunkInformation != null ? options.ChunkInformation!.TotalChunks : 1;
                int concurrentChunkCount = SystemHelper.CalculateConcurrency(options.IsChunked, chunkSizeInMB);
                ReadOnlyMemory<byte> key = PasswordHelper.GetSlicedKey(provider.KeySize);
                await using FileStream vaultFS = new FileStream(_session.VAULTPATH!, FileMode.Open, FileAccess.ReadWrite);
                await using FileStream fileFS = new FileStream(filePath!, FileMode.Open, FileAccess.Read);
                _session.VAULT_READER.AddAndSaveMetadataOffsets(vaultFS, vaultFS.Seek(0, SeekOrigin.End));

                byte[] paddedFileOptions = null!;
                try
                {
                    paddedFileOptions = _encryptionOptionsService.EncryptAndPadFileEncryptionOptions(options);
                    //Seek to the end of file to make sure its saved at the end and not after metadata data
                    vaultFS.Seek(0, SeekOrigin.End);
                    vaultFS.Write(paddedFileOptions);

                }
                finally
                {
                    if (paddedFileOptions is not null) CryptographicOperations.ZeroMemory(paddedFileOptions);
                }
                await EncryptChunks(fileFS, vaultFS, totalChunks, concurrentChunkCount, chunkSizeInMB, provider.EncryptionAlgorithm, key, context);
            }
            finally
            {
                options.Dispose();
            }
        }

        private async Task EncryptChunks(Stream fileFS, Stream vaultFS, int totalChunks, int concurrentChunkCount, ushort chunkSizeInMB, EncryptionAlgorithm.IEncryptionAlgorithm encryptionAlgorithm, ReadOnlyMemory<byte> key, ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(fileFS);
            ArgumentNullException.ThrowIfNull(vaultFS);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(totalChunks);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(concurrentChunkCount);
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);
            if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));
            ArgumentNullException.ThrowIfNull(context);

            var tasks = new List<Task>();
            var results = new ConcurrentDictionary<int, byte[]>();
            int nextToWrite = 0;
            int chunkIndex = 0;
            byte[] buffer = new byte[Math.Min((chunkSizeInMB * 1024 * 1024), fileFS.Length)];

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

                    if (tasks.Any(task => task.IsFaulted)) throw new VaultException(VaultException.ErrorContext.Encrypt, VaultException.ErrorReason.TaskFaulted);
                    if (tasks.Count >= concurrentChunkCount)
                    {
                        await Task.WhenAny(tasks);
                        tasks.RemoveAll(task => task.IsCompleted);
                    }

                    tasks.Add(Task.Run(() =>
                    {
                        context.CancellationToken.ThrowIfCancellationRequested();
                        byte[] encrypted = null!;
                        try
                        {
                            encrypted = encryptionAlgorithm.EncryptBytes(chunk, key.Span);
                            results.TryAdd(currentIndex, encrypted);
                        }
                        finally
                        {
                            if (chunk is not null) CryptographicOperations.ZeroMemory(chunk);
                            //encrypted field gets cleaned in FileHelper.WriteReadyChunk after writing
                        }
                        _fileService.WriteReadyChunk(results, ref nextToWrite, currentIndex, vaultFS, writeLock);
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
    }
}
