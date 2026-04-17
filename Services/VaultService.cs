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
        public void TrimVault(ProgressionContext context);
        /// <summary>
        /// Deletes file from vault by either shortening file length or zeroing out the blocks
        /// </summary>
        /// <param name="offset">Offset to the file inside vault</param>
        /// <param name="context">Context to display progression</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="offset"/> is set to negative value</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is set to <see cref="null"/></exception>
        public void DeleteFileFromVault(long offset, ProgressionContext context);
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
                    Directory.CreateDirectory(folderPath);
                    createdDirectory = true;
                }
                NormalizedPath vaultPath = NormalizedPath.From($"{folderPath}\\{vaultName}.vlt");
                IVaultReader reader = _registry.GetVaultReader(VaultSession.NewestVaultVersion);
                byte[] salt = PasswordHelper.GenerateRandomSalt(reader.SaltSize);
                SecureBuffer.SecureLargeBuffer vaultHeader = null!;
                SecureBuffer.SecureLargeBuffer encryptedMetadata = null!;
                try
                {
                    vaultHeader = reader.PrepareVaultHeader(salt, iterations);
                    _session.CreateSession(vaultPath, reader, password, salt, iterations);
                    encryptedMetadata = reader.VaultEncryption(new byte[sizeof(ushort) + reader.MetadataOffsetsSize]);
                    try
                    {
                        using (FileStream vaultFS = new FileStream(vaultPath, FileMode.Create, FileAccess.Write))
                        {
                            vaultFS.Write(vaultHeader.AsSpan);
                            vaultFS.Write(encryptedMetadata.AsSpan);
                        }
                    }
                    catch (Exception)
                    {
                        //Failed writing to vault, delete entire file
                        File.Delete(vaultPath);
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
                    vaultHeader?.Dispose();
                    encryptedMetadata?.Dispose();
                }
            }
            catch (Exception)
            {
                if (createdDirectory) Directory.Delete(folderPath);
                throw;
            }
        }

        public void CreateSessionFromFile(ReadOnlySpan<byte> password, NormalizedPath path)
        {
            if(password.Length == 0) { throw new ArgumentException("Provided empty password"); }
            ArgumentNullException.ThrowIfNullOrWhiteSpace(path);

            using FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            byte version = (byte)fs.ReadByte();

            IVaultReader reader = _registry.GetVaultReader(version);
            int iterations = reader.ReadIterationsNumber(fs);
            using (SecureBuffer.SecureLargeBuffer salt = reader.ReadSalt(fs))
            {
                _session.CreateSession(path, reader, password, salt.AsSpan, iterations);
            }
            RefreshEncryptedFilesList(fs);
        }

        public void RefreshEncryptedFilesList(Stream vaultFS)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);

            try
            {
                _session.ENCRYPTED_FILES.Clear();
                PopulateEncryptedFilesList(vaultFS);
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
                            _session.ENCRYPTED_FILES.Add(offset, new EncryptedFileInfo(Encoding.UTF8.GetString(fileEncryptionOptions.FileName.AsSpan), fileEncryptionOptions.FileSize, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[fileEncryptionOptions.EncryptionAlgorithm]));
                        }
                        catch (ArgumentException)
                        {
                            //Dictionary entry with the same key already exists, replace it
                            _session.ENCRYPTED_FILES[offset] = new EncryptedFileInfo(Encoding.UTF8.GetString(fileEncryptionOptions.FileName.AsSpan), fileEncryptionOptions.FileSize, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[fileEncryptionOptions.EncryptionAlgorithm]);
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

        public void TrimVault(ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            _systemService.CheckFreeSpace(_session.VAULTPATH);
            using FileStream vaultfs = new FileStream(_session.VAULTPATH, FileMode.Open, FileAccess.Read);
            //Remove the last 4 characters from a string (.vlt) before adding new text
            using FileStream newVaultfs = new FileStream(_session.VAULTPATH.Value[..^4] + "_TRIMMED.vlt", FileMode.Create);

            var reader = _session.VAULT_READER;
            _fileService.CopyPartOfFile(vaultfs, 0, (ulong)reader.HeaderSize, newVaultfs, newVaultfs.Seek(0, SeekOrigin.End));
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

                    if (currentOffset > vaultfs.Length)
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
                    EncryptionOptions.FileEncryptionOptions encryptionOptions = null!;
                    try
                    {
                        encryptionOptions = _encryptionOptionsService.GetDecryptedFileEncryptionOptions(vaultfs, currentOffset);
                        fileSize = encryptionOptions.FileSize;
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
                    ulong fileMinimum = (ulong)(vaultfs.Length - currentOffset);
                    ulong toRead = new[] { offsetMinimum, optionsMinimum, fileMinimum }.Min();

                    newVaultOffsets[i] = newVaultfs.Seek(0, SeekOrigin.End);
                    _fileService.CopyPartOfFile(vaultfs, currentOffset, toRead, newVaultfs, newVaultOffsets[i]);
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

        public void DeleteFileFromVault(long offset, ProgressionContext context)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentNullException.ThrowIfNull(context);


            using FileStream vaultFS = new FileStream(_session.VAULTPATH, FileMode.Open, FileAccess.ReadWrite);
            var fileList = _session.ENCRYPTED_FILES.ToList();
            if(_session.ENCRYPTED_FILES.Count == 1)
            {
                //Deleting only file in vault, set the size to empty vault file
                vaultFS.SetLength(_session.VAULT_READER.HeaderSize);
            }
            else if (_session.ENCRYPTED_FILES.Last().Key == offset)
            {
                //Deleting last file in vault, set the size to remove last file
                vaultFS.SetLength(offset);
            }
            else
            {
                //Deleting file that isn't last or only, zero out the block
                var encryptionMetadataSize = _session.VAULT_READER.EncryptionOptionsSize;
                int currentKey = fileList.FindIndex(file => file.Key == offset);
                EncryptionOptions.FileEncryptionOptions encryptionOptions = null!;
                //Calculate length incase of partially written file
                ulong length = 0;
                try
                {
                    encryptionOptions = _encryptionOptionsService.GetDecryptedFileEncryptionOptions(vaultFS, offset);
                    length = Math.Min(encryptionOptions.FileSize + (ulong)encryptionMetadataSize, (ulong)(fileList[currentKey + 1].Key - fileList[currentKey].Key));
                }
                catch (Exception)
                {
                    //Encryption options are corrupted, zero out the part until next key
                    length = (ulong)(fileList[currentKey + 1].Key - fileList[currentKey].Key);
                }
                finally
                {
                    encryptionOptions?.Dispose();
                }

                _fileService.ZeroOutPartOfFile(vaultFS, offset, length);
            }
            _session.VAULT_READER.RemoveAndSaveMetadataOffsets(vaultFS, checked((ushort)fileList.FindIndex(file => file.Key == offset)));
            context.Increment();
        }
    }
}
