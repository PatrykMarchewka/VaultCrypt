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
        public void CreateVault(NormalizedPath folderPath, string vaultName, byte[] password, int iterations);
        public void CreateSessionFromFile(byte[] password, NormalizedPath path);
        public void TrimVault(ProgressionContext context);
        public void DeleteFileFromVault(KeyValuePair<long, EncryptedFileInfo> FileMetadataEntry, ProgressionContext context);
        public void RefreshEncryptedFilesList(Stream vaultFS);
    }

    public class VaultService : IVaultService
    {
        private readonly IFileService _fileService;
        private readonly IVaultSession _session;
        private readonly IEncryptionOptionsService _encryptionOptionsService;

        public VaultService(IFileService fileService, IVaultSession session, IEncryptionOptionsService encryptionOptionsService)
        {
            this._fileService = fileService;
            this._session = session;
            this._encryptionOptionsService = encryptionOptionsService;
        }

        /// <summary>
        /// Creates vault file (.vlt)
        /// </summary>
        /// <param name="folderPath">Path to the folder in which vault file should be placed</param>
        /// <param name="vaultName">Name for the vault file</param>
        /// <param name="password">Password to encrypt the vault with</param>
        /// <param name="iterations">Number of PBKDF2 iterations</param>
        /// <exception cref="ArgumentNullException"><paramref name="folderPath"/>, <paramref name="vaultName"/> or <paramref name="password"/> is <see cref="null"/></exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is negative or set to zero</exception>
        public void CreateVault(NormalizedPath folderPath, string vaultName, byte[] password, int iterations)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(folderPath);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(vaultName);
            ArgumentNullException.ThrowIfNull(password);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);

            if (!Directory.Exists(folderPath)) Directory.CreateDirectory(folderPath!);
            NormalizedPath vaultPath = NormalizedPath.From($"{folderPath}\\{vaultName}.vlt");
            VaultReader reader = VaultRegistry.GetVaultReader(VaultSession.NewestVaultVersion);
            byte[] salt = null!;
            byte[] buffer = null!;
            byte[] encryptedMetadata = null!;
            byte[] data = null!;
            try
            {
                salt = PasswordHelper.GenerateRandomSalt(reader.SaltSize);
                buffer = reader.PrepareVaultHeader(salt, iterations);
                _session.CreateSession(vaultPath, reader, password, salt, iterations);
                encryptedMetadata = reader.VaultEncryption(new byte[sizeof(ushort) + reader.MetadataOffsetsSize]);
                data = new byte[buffer.Length + encryptedMetadata.Length];
                Buffer.BlockCopy(buffer, 0, data, 0, buffer.Length);
                Buffer.BlockCopy(encryptedMetadata, 0, data, buffer.Length, encryptedMetadata.Length);
                File.WriteAllBytes(vaultPath!, data);
            }
            finally
            {
                if (salt is not null) CryptographicOperations.ZeroMemory(salt);
                if (buffer is not null) CryptographicOperations.ZeroMemory(buffer);
                if (encryptedMetadata is not null) CryptographicOperations.ZeroMemory(encryptedMetadata);
                if (data is not null) CryptographicOperations.ZeroMemory(data);
            }
        }

        /// <summary>
        /// Creates new vault session
        /// </summary>
        /// <param name="password">Password to unlock the vault with</param>
        /// <param name="path">Path to the vault with extension</param>
        public void CreateSessionFromFile(byte[] password, NormalizedPath path)
        {
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(path);

            using FileStream fs = new FileStream(path!, FileMode.Open, FileAccess.Read);
            Span<byte> buffer = stackalloc byte[1];
            fs.ReadExactly(buffer);
            byte version = buffer[0];

            VaultReader reader = VaultRegistry.GetVaultReader(version);
            int iterations = reader.ReadIterationsNumber(fs);
            byte[] salt = null!;
            try
            {
                salt = reader.ReadSalt(fs);
                _session.CreateSession(path, reader, password, salt, iterations);
            }
            finally
            {
                if (salt is not null) CryptographicOperations.ZeroMemory(salt);
            }
            RefreshEncryptedFilesList(fs);
        }

        public void RefreshEncryptedFilesList(Stream vaultFS)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);

            try
            {
                _session.ENCRYPTED_FILES.Clear();
                _session.VAULT_READER.PopulateEncryptedFilesList(vaultFS);
            }
            finally
            {
                _session.RasiseEncryptedFileListUpdated();
            }
        }

        public void TrimVault(ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            SystemHelper.CheckFreeSpace(_session.VAULTPATH);
            using FileStream vaultfs = new FileStream(_session.VAULTPATH!, FileMode.Open, FileAccess.Read);
            using FileStream newVaultfs = new FileStream(_session.VAULTPATH + "_TRIMMED.vlt", FileMode.Create);

            var reader = _session.VAULT_READER;
            _fileService.CopyPartOfFile(vaultfs, 0, (ulong)reader.HeaderSize, newVaultfs, newVaultfs.Seek(0, SeekOrigin.End));
            var fileList = _session.ENCRYPTED_FILES.ToList();
            int fileListCount = fileList.Count;

            long[] newVaultOffsets = new long[fileListCount];
            long[] trimmedOffsets = null!;
            try
            {
                for (int i = 0; i < fileListCount; i++)
                {
                    context.CancellationToken.ThrowIfCancellationRequested();
                    long currentOffset = fileList[i].Key;
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
                        if (encryptionOptions is not null) encryptionOptions.Dispose();
                    }

                    //Calculating toread to allow copying of partially encrypted files
                    ulong toread = Math.Min((ulong)(nextOffset - currentOffset), (ulong)reader.EncryptionOptionsSize + fileSize);
                    newVaultOffsets[i] = newVaultfs.Seek(0, SeekOrigin.End);
                    _fileService.CopyPartOfFile(vaultfs, currentOffset, toread, newVaultfs, newVaultOffsets[i]);
                    //Reporting current index + 1 because i is zero based while user gets to see 1 based indexing, total is filelList.Count + 1 because last action is saving new header
                    context.Progress.Report(new ProgressStatus(i + 1, fileList.Count + 1));
                }
                //Delete offsets pointing to 0 (empty data from options that werent properly added) and duplicates
                trimmedOffsets = newVaultOffsets.Where((offset, index) => offset != 0).Distinct().ToArray();
                reader.SaveMetadataOffsets(newVaultfs, trimmedOffsets);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(newVaultOffsets.AsSpan()));
                if (trimmedOffsets is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(trimmedOffsets.AsSpan()));
            }

            context.Progress.Report(new ProgressStatus(fileListCount + 1, fileListCount + 1));
        }

        public void DeleteFileFromVault(KeyValuePair<long, EncryptedFileInfo> FileMetadataEntry, ProgressionContext context)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(FileMetadataEntry.Key);
            ArgumentNullException.ThrowIfNull(context);


            using FileStream vaultFS = new FileStream(_session.VAULTPATH!, FileMode.Open, FileAccess.ReadWrite);
            var fileList = _session.ENCRYPTED_FILES.ToList();
            //If the file is at the end, just trim the entire file, otherwise zero out the block
            if (_session.ENCRYPTED_FILES.Last().Equals(FileMetadataEntry))
            {
                vaultFS.SetLength(FileMetadataEntry.Key);
            }
            else
            {
                //Calculate length incase of partially written file
                var encryptionMetadataSize = _session.VAULT_READER.EncryptionOptionsSize;
                int currentKey = fileList.FindIndex(file => file.Key == FileMetadataEntry.Key);
                EncryptionOptions.FileEncryptionOptions encryptionOptions = null!;
                ulong length = 0;
                try
                {
                    encryptionOptions = _encryptionOptionsService.GetDecryptedFileEncryptionOptions(vaultFS, FileMetadataEntry.Key);
                    length = Math.Min(encryptionOptions.FileSize + (ulong)encryptionMetadataSize, (ulong)(fileList[currentKey + 1].Key - fileList[currentKey].Key));
                }
                catch (Exception)
                {
                    //Encryption options are corrupted, zero out the part until next key
                    length = (ulong)(fileList[currentKey + 1].Key - fileList[currentKey].Key);
                }
                finally
                {
                    if (encryptionOptions is not null) encryptionOptions.Dispose();
                }

                _fileService.ZeroOutPartOfFile(vaultFS, FileMetadataEntry.Key, length);
            }
            _session.VAULT_READER.RemoveAndSaveMetadataOffsets(vaultFS, checked((ushort)fileList.FindIndex(file => file.Equals(FileMetadataEntry))));
            context.Progress.Report(new ProgressStatus(1, 1));
        }
    }
}
