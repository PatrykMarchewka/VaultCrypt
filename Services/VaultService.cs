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
        public void TrimVault(ProgressionContext context);
        public void DeleteFileFromVault(KeyValuePair<long, EncryptedFileInfo> FileMetadataEntry, ProgressionContext context);
    }

    public class VaultService : IVaultService
    {
        private readonly IFileService _fileService;
        public VaultService(IFileService fileService)
        {
            this._fileService = fileService;
        }

        public void TrimVault(ProgressionContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            SystemHelper.CheckFreeSpace(VaultSession.CurrentSession.VAULTPATH);
            using FileStream vaultfs = new FileStream(VaultSession.CurrentSession.VAULTPATH!, FileMode.Open, FileAccess.Read);
            using FileStream newVaultfs = new FileStream(VaultSession.CurrentSession.VAULTPATH + "_TRIMMED.vlt", FileMode.Create);

            var reader = VaultSession.CurrentSession.VAULT_READER;
            _fileService.CopyPartOfFile(vaultfs, 0, (ulong)reader.HeaderSize, newVaultfs, newVaultfs.Seek(0, SeekOrigin.End));
            var fileList = VaultSession.CurrentSession.ENCRYPTED_FILES.ToList();
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
                        encryptionOptions = EncryptionOptions.GetDecryptedFileEncryptionOptions(vaultfs, currentOffset);
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


            using FileStream vaultFS = new FileStream(VaultSession.CurrentSession.VAULTPATH!, FileMode.Open, FileAccess.ReadWrite);
            var fileList = VaultSession.CurrentSession.ENCRYPTED_FILES.ToList();
            //If the file is at the end, just trim the entire file, otherwise zero out the block
            if (VaultSession.CurrentSession.ENCRYPTED_FILES.Last().Equals(FileMetadataEntry))
            {
                vaultFS.SetLength(FileMetadataEntry.Key);
            }
            else
            {
                //Calculate length incase of partially written file
                var encryptionMetadataSize = VaultSession.CurrentSession.VAULT_READER.EncryptionOptionsSize;
                int currentKey = fileList.FindIndex(file => file.Key == FileMetadataEntry.Key);
                EncryptionOptions.FileEncryptionOptions encryptionOptions = null!;
                ulong length = 0;
                try
                {
                    encryptionOptions = EncryptionOptions.GetDecryptedFileEncryptionOptions(vaultFS, FileMetadataEntry.Key);
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
            VaultSession.CurrentSession.VAULT_READER.RemoveAndSaveMetadataOffsets(vaultFS, checked((ushort)fileList.FindIndex(file => file.Equals(FileMetadataEntry))));
            context.Progress.Report(new ProgressStatus(1, 1));
        }
    }
}
