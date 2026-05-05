using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Services
{
    public interface IVaultService
    {
        /// <summary>
        /// Creates vault file (.vlt)
        /// </summary>
        /// <param name="folderPath">Path to the folder in which vault file should be placed</param>
        /// <param name="vaultName">Name for the vault file</param>
        /// <param name="password">Password to encrypt the vault with</param>
        /// <param name="iterations">Number of iterations used when deriving the key</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="folderPath"/>, <paramref name="vaultName"/> or <paramref name="password"/> is set to <see cref="null"/></exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="folderPath"/>, <paramref name="vaultName"/> or <paramref name="password"/> value is empty or set to whitespace only characters</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="iterations"/> is set to negative or zero value</exception>
        public void CreateVault(NormalizedPath folderPath, string vaultName, ReadOnlySpan<byte> password, int iterations);
        /// <summary>
        /// Creates new vault session from vault file
        /// </summary>
        /// <param name="password">Password to unlock the vault with</param>
        /// <param name="path">Path to the vault file</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="path"/> is set to <see cref="null"/></exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty or <paramref name="path"/> value is empty or set to whitespace only characters</exception>
        public void CreateSessionFromFile(ReadOnlySpan<byte> password, NormalizedPath path);
        /// <summary>
        /// Recreates existing vault without zeroed blocks or corrupted files
        /// </summary>
        /// <param name="context">Context to display progression</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is set to <see cref="null"/></exception>
        public Task TrimVault(ProgressionContext context);
        /// <summary>
        /// Deletes file from vault by either shortening file length or zeroing out the blocks
        /// </summary>
        /// <param name="offset">Offset to the file inside vault</param>
        /// <param name="context">Context to display progression</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="offset"/> is set to negative value</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is set to <see cref="null"/></exception>
        public Task DeleteFileFromVault(long offset, ProgressionContext context);
        /// <summary>
        /// Refreshes information in <see cref="IVaultSession.ENCRYPTED_FILES"/>
        /// </summary>
        /// <param name="vaultFS">Vault to read data from</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="vaultFS"/> is set to <see cref="null"/></exception>
        public void RefreshEncryptedFilesList(Stream vaultFS);
    }

    public class VaultService : IVaultService
    {
        private readonly IFileService _fileService;
        private readonly IVaultSession _session;
        private readonly IEncryptionOptionsService _encryptionOptionsService;
        private readonly ISystemService _systemService;
        private readonly IVaultRegistry _registry;

        public VaultService(IFileService fileService, IVaultSession session, IEncryptionOptionsService encryptionOptionsService, ISystemService systemService, IVaultRegistry registry)
        {
            this._fileService = fileService;
            this._session = session;
            this._encryptionOptionsService = encryptionOptionsService;
            this._systemService = systemService;
            this._registry = registry;
        }

        public void CreateVault(NormalizedPath folderPath, string vaultName, ReadOnlySpan<byte> password, int iterations)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(folderPath);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(vaultName);
            if(password.IsEmpty) { throw new ArgumentException("Provided empty password"); }
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);


            bool createdDirectory = false;
            try
            {
                if (!Directory.Exists(folderPath))
                {
                    RetryHelper.TryUntilSuccess(tryAction: () => { Directory.CreateDirectory(folderPath); createdDirectory = true; }, maxRetries: 10);
                }
                NormalizedPath vaultPath = NormalizedPath.From($"{folderPath}\\{vaultName}.vlt");
                IVaultReader reader = _registry.GetVaultReader(VaultSession.NewestVaultVersion);
                byte[] salt = PasswordHelper.GenerateRandomSalt(reader.SaltSize);
                try
                {
                    using SecureBuffer.SecureLargeBuffer vaultHeader = reader.PrepareVaultHeader(salt, iterations);
                    _session.CreateSession(vaultPath, reader, password, salt, iterations);
                    using SecureBuffer.SecureLargeBuffer encryptedMetadata = reader.VaultEncryption(new byte[sizeof(ushort) + reader.MetadataOffsetsSize]);
                    try
                    {
                        RetryHelper.TryUntilSuccess(tryAction: () =>
                        {
                            using (FileStream vaultFS = new FileStream(vaultPath, FileMode.Create, FileAccess.Write))
                            {
                                vaultFS.Write(vaultHeader.AsSpan);
                                vaultFS.Write(encryptedMetadata.AsSpan);
                            }
                        }, maxRetries: 10);
                    }
                    catch (Exception)
                    {
                        //Failed writing to vault, delete entire file
                        try
                        {
                            RetryHelper.TryUntilSuccess(tryAction: () => File.Delete(vaultPath), maxRetries: 10);
                        }
                        catch (Exception)
                        {
                            throw new VaultCrypt.Exceptions.VaultUIException($"Could not delete leftover file at {vaultPath}");
                        }
                        throw;
                    }
                    
                }
                catch (Exception)
                {
                    //Creating vault failed, reset session to avoid holding stale data
                    _session.Dispose();
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(salt);
                }
            }
            catch (Exception)
            {
                try
                {
                    if (createdDirectory) RetryHelper.TryUntilSuccess(tryAction: () => Directory.Delete(folderPath), maxRetries: 10);
                }
                catch (Exception)
                {
                    throw new VaultCrypt.Exceptions.VaultUIException($"Could not delete leftover folder at {folderPath}");
                }
                throw;
            }
        }

        public void CreateSessionFromFile(ReadOnlySpan<byte> password, NormalizedPath path)
        {
            if(password.Length == 0) { throw new ArgumentException("Provided empty password"); }
            ArgumentNullException.ThrowIfNullOrWhiteSpace(path);


            using FileStream fs = RetryHelper.TryUntilSuccess(tryAction: () => new FileStream(path, FileMode.Open, FileAccess.Read), maxRetries: 10);
            byte version = RetryHelper.TryUntilSuccess(tryAction: () => (byte)fs.ReadByte(), maxRetries: 10);

            IVaultReader reader = _registry.GetVaultReader(version);
            int iterations = RetryHelper.TryUntilSuccess(tryAction: () => reader.ReadIterationsNumber(fs), maxRetries: 10);

            SecureBuffer.SecureLargeBuffer salt = null!;
            try
            {
                salt = RetryHelper.TryUntilSuccess(tryAction: () => reader.ReadSalt(fs), maxRetries: 10);
                _session.CreateSession(path, reader, password, salt.AsSpan, iterations);
            }
            finally
            {
                salt?.Dispose();
            }
            RefreshEncryptedFilesList(fs);
        }

        public void RefreshEncryptedFilesList(Stream vaultFS)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);

            try
            {
                _session.ENCRYPTED_FILES.Clear();
                RetryHelper.TryUntilSuccess(tryAction: () => PopulateEncryptedFilesList(vaultFS), maxRetries: 10);
            }
            finally
            {
                _session.RaiseEncryptedFileListUpdated();
            }
        }

        /// <summary>
        /// Populates <see cref="IVaultSession.ENCRYPTED_FILES"/> list with the information from the <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Vault file to read from</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        private void PopulateEncryptedFilesList(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            long[] offsets = null!;
            try
            {
                offsets = _session.VAULT_READER.ReadMetadataOffsets(stream);
                foreach (long offset in offsets)
                {
                    EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = null!;
                    try
                    {
                        fileEncryptionOptions = _encryptionOptionsService.GetDecryptedFileEncryptionOptions(stream, offset);
                        try
                        {
                            _session.ENCRYPTED_FILES.Add(offset, new EncryptedFileInfo(fileEncryptionOptions.GetFileName(), fileEncryptionOptions.FileSize, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[fileEncryptionOptions.EncryptionAlgorithm]));
                        }
                        catch (ArgumentException)
                        {
                            //Dictionary entry with the same key already exists, replace it
                            _session.ENCRYPTED_FILES[offset] = new EncryptedFileInfo(fileEncryptionOptions.GetFileName(), fileEncryptionOptions.FileSize, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[fileEncryptionOptions.EncryptionAlgorithm]);
                        }

                    }
                    catch (Exception)
                    {
                        _session.ENCRYPTED_FILES.Add(offset, new EncryptedFileInfo(null, 0, null));
                    }
                    finally
                    {
                        fileEncryptionOptions?.Dispose();
                    }
                }
            }
            finally
            {
                if (offsets is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(offsets.AsSpan()));
            }
        }

        public async Task TrimVault(ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            await RetryHelper.TryUntilSuccessAsync(
                tryAction: () => _systemService.CheckFreeSpace(_session.VAULTPATH),
                catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.SystemCheckFailed));

            FileStream vaultfs = null!;
            long oldVaultSize;
            FileStream newVaultfs = null!;
            try
            {
                try
                {
                    vaultfs = await RetryHelper.TryUntilSuccessAsync(
                        tryAction: () => vaultfs = new FileStream(_session.VAULTPATH, FileMode.Open, FileAccess.Read),
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.CreatingStreamFailed));
                    oldVaultSize = RetryHelper.TryUntilSuccess(tryAction: () => vaultfs.Length, catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed));
                }
                catch (Exception)
                {
                    context.ReportPermStatus(ProgressFailure.ProgressPermFailure.IOOperationFailed, "Could not open vault file, aborting operation");
                    context.ForceFinish();
                    return;
                }

                string newVaultPath = _session.VAULTPATH.Value[..^4] + "_TRIMMED.vlt"; //Remove the last 4 characters from original vault path (.vlt) before adding new text
                try
                {
                    newVaultfs = await RetryHelper.TryUntilSuccessAsync(
                        tryAction: () => newVaultfs = new FileStream(newVaultPath, FileMode.Create, FileAccess.ReadWrite, FileShare.Delete),
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.CreatingStreamFailed));
                }
                catch (Exception)
                {
                    context.ReportPermStatus(ProgressFailure.ProgressPermFailure.IOOperationFailed, "Could not create new vault file, aborting operation");
                    context.ForceFinish();
                    return;
                }
                var reader = _session.VAULT_READER;

                try
                {
                    await RetryHelper.TryUntilSuccessAsync(
                        tryAction: () => _fileService.CopyPartOfFile(source: vaultfs!, offset: 0, length: (ulong)reader.HeaderSize, destination: newVaultfs!, destinationOffset: newVaultfs!.Seek(0, SeekOrigin.End)),
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                }
                catch (Exception)
                {
                    //Couldnt copy vault header, delete new vault file
                    context.ReportPermStatus(ProgressFailure.ProgressPermFailure.IOOperationFailed, "Could not copy vault header, aborting operation");
                    try
                    {
                        await RetryHelper.TryUntilSuccessAsync(
                            tryAction: () => File.Delete(newVaultPath),
                            catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.DeletingFileFailed));
                    }
                    catch (Exception)
                    {
                        context.ReportPermStatus(ProgressFailure.ProgressPermFailure.IOOperationFailed, $"Could not delete leftover file at {newVaultPath}");
                    }
                    context.ForceFinish();
                    return;
                }
                
                var fileList = _session.ENCRYPTED_FILES.ToList();
                int fileListCount = fileList.Count;
                //Total is filelList.Count + 1 because last action is saving new header
                context.SetTotal(fileListCount + 1);

                long[] newVaultOffsets = new long[fileListCount];
                try
                {
                    for (int i = 0; i < fileListCount; i++)
                    {
                        context.CancellationToken.ThrowIfCancellationRequested();
                        long currentOffset = fileList[i].Key;

                        if (currentOffset >= oldVaultSize)
                        {
                            //Offset points outside vault, skip it
                            context.Increment();
                            continue;
                        }

                        long nextOffset = long.MaxValue;
                        if (i + 1 < fileListCount)
                        {
                            nextOffset = fileList[i + 1].Key;
                        }

                        ulong fileSize = 0;
                        string fileName;
                        EncryptionOptions.FileEncryptionOptions encryptionOptions = null!;
                        try
                        {
                            encryptionOptions = await RetryHelper.TryUntilSuccessAsync(
                                    tryAction: () => _encryptionOptionsService.GetDecryptedFileEncryptionOptions(vaultfs, currentOffset),
                                    catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed),
                                    shouldRetry: ex => ex is IOException);
                            fileSize = encryptionOptions.FileSize;
                            fileName = encryptionOptions.GetFileName();
                        }
                        catch
                        {
                            //Encryption options cant be read due to corruption, skip that offset
                            continue;
                        }
                        finally
                        {
                            encryptionOptions?.Dispose();
                        }

                        /*
                         * offsetMinimum represents the distance between current offset and next offset
                         * optionsMinimum represents the size of encryption options metadata and encrypted file itself
                         * fileMinimum represents the distance between current position and end of stream
                         * 
                         * We calculate the lowest amount of all three options to copy as an attempt to preserve the encrypted file as much as we can
                         * offsetMinimum is lowest -> File is partially saved, we dont want to overstep onto another file
                         * optionsMinimum is lowest -> File is fully saved, however there is unknown space between end of it and next file, we don't want to copy extra trash
                         * fileMinimum is lowest -> End of stream reached, we can't copy more
                         */
                        ulong offsetMinimum = (ulong)(nextOffset - currentOffset);
                        ulong optionsMinimum = reader.EncryptionOptionsSize + fileSize;
                        ulong fileMinimum = (ulong)(oldVaultSize - currentOffset);
                        ulong toRead = new[] { offsetMinimum, optionsMinimum, fileMinimum }.Min();

                        newVaultOffsets[i] = newVaultfs.Seek(0, SeekOrigin.End);
                        try
                        {
                            await RetryHelper.TryUntilSuccessAsync(
                                tryAction: () => _fileService.CopyPartOfFile(vaultfs, currentOffset, toRead, newVaultfs, newVaultOffsets[i]),
                                catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                        }
                        catch (Exception)
                        {
                            context.ReportPermStatus(ProgressFailure.ProgressPermFailure.IOOperationFailed, $"Could not copy file {fileName}");
                        }
                        context.Increment();
                    }
                }
                finally
                {
                    //Delete offsets pointing to 0 (empty data from options that werent properly added) and duplicates
                    long[] trimmedOffsets = newVaultOffsets.Where((offset, index) => offset != 0).Distinct().ToArray();
                    reader.SaveMetadataOffsets(newVaultfs, trimmedOffsets);

                    CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(newVaultOffsets.AsSpan()));
                    CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(trimmedOffsets.AsSpan()));
                }
                context.Increment();
            }
            finally
            {
                vaultfs?.Dispose();
                newVaultfs?.Dispose();
            }
        }

        public async Task DeleteFileFromVault(long offset, ProgressionContext context)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(offset, _session.VAULT_READER.HeaderSize);
            ArgumentNullException.ThrowIfNull(context);

            FileStream vaultFS = null!;
            try
            {
                try
                {
                    vaultFS = await RetryHelper.TryUntilSuccessAsync(
                        tryAction: () => new FileStream(_session.VAULTPATH, FileMode.Open, FileAccess.ReadWrite),
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed));
                }
                catch (Exception)
                {
                    context.ReportPermStatus(ProgressFailure.ProgressPermFailure.IOOperationFailed, "Could not open vault file, aborting operation");
                    context.ForceFinish();
                    return;
                }
                var fileList = _session.ENCRYPTED_FILES.ToList();
                if (_session.ENCRYPTED_FILES.Count == 1)
                {
                    //Deleting only file in vault, set the size to empty vault file
                    await RetryHelper.TryUntilSuccessAsync(
                        tryAction: () => vaultFS.SetLength(_session.VAULT_READER.HeaderSize),
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                }
                else if (_session.ENCRYPTED_FILES.Last().Key == offset)
                {
                    //Deleting last file in vault, set the size to remove last file
                    await RetryHelper.TryUntilSuccessAsync(
                        tryAction: () => vaultFS.SetLength(offset),
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                }
                else
                {
                    //Deleting file that isn't last or only, zero out the block
                    var encryptionMetadataSize = _session.VAULT_READER.EncryptionOptionsSize;
                    int currentKey = fileList.FindIndex(file => file.Key == offset);
                    ulong offsetDistance = (ulong)(fileList[currentKey + 1].Key - fileList[currentKey].Key);
                    EncryptionOptions.FileEncryptionOptions encryptionOptions = null!;
                    //Calculate length incase of partially written file
                    ulong length = 0;
                    try
                    {
                        encryptionOptions = await RetryHelper.TryUntilSuccessAsync(
                                        tryAction: () => _encryptionOptionsService.GetDecryptedFileEncryptionOptions(vaultFS, offset),
                                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.ReadingFromStreamFailed),
                                        shouldRetry: ex => ex is IOException);

                        ulong expectedEncryptedSize = encryptionOptions.FileSize + encryptionMetadataSize;
                        length = Math.Min(encryptionOptions.FileSize + (ulong)encryptionMetadataSize, (ulong)(fileList[currentKey + 1].Key - fileList[currentKey].Key));
                    }
                    catch (Exception)
                    {
                        //Encryption options are corrupted, zero out the part until next key
                        length = offsetDistance;
                    }
                    finally
                    {
                        encryptionOptions?.Dispose();
                    }

                    await RetryHelper.TryUntilSuccessAsync(
                        tryAction: () => _fileService.ZeroOutPartOfFile(vaultFS, offset, length),
                        catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed));
                }

                await RetryHelper.TryUntilSuccessAsync(
                    tryAction: () => _session.VAULT_READER.RemoveAndSaveMetadataOffsets(vaultFS, checked((ushort)fileList.FindIndex(file => file.Key == offset))),
                    catchAction: () => context.ReportTempStatus(ProgressFailure.ProgressTempFailure.WritingToFileFailed),
                    shouldRetry: ex => ex is not OverflowException);

                context.Increment();

            }
            finally
            {
                vaultFS?.Dispose();
            }
        }
    }
}
