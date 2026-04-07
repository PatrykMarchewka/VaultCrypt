using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt.Services
{
    public interface IEncryptionOptionsService
    {
        public EncryptionOptions.FileEncryptionOptions PrepareEncryptionOptions(FileInfo fileInfo, EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, ushort chunkSizeInMB);
        public SecureBuffer.SecureLargeBuffer EncryptAndPadFileEncryptionOptions(EncryptionOptions.FileEncryptionOptions options);
        public EncryptionOptions.FileEncryptionOptions GetDecryptedFileEncryptionOptions(Stream vaultFS, long metadataOffset);

    }

    public class EncryptionOptionsService : IEncryptionOptionsService
    {
        private readonly IVaultSession _session;
        public EncryptionOptionsService(IVaultSession session)
        {
            this._session = session;
        }

        public EncryptionOptions.FileEncryptionOptions PrepareEncryptionOptions(FileInfo fileInfo, EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, ushort chunkSizeInMB)
        {
            ArgumentNullException.ThrowIfNull(fileInfo);
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);

            SecureBuffer.SecureLargeBuffer fileName = new SecureBuffer.SecureLargeBuffer(Encoding.UTF8.GetByteCount(fileInfo.Name));
            Encoding.UTF8.GetBytes(fileInfo.Name, fileName.AsSpan);
            bool chunked = false;
            EncryptionOptions.ChunkInformation? chunkInformation = null;

            if (fileInfo.Length > (chunkSizeInMB * 1024 * 1024))
            {
                chunked = true;
                long chunkSize = chunkSizeInMB * 1024 * 1024;
                long chunkNumber = (fileInfo.Length / chunkSize) + 1;
                long lastChunk = fileInfo.Length - ((chunkNumber - 1) * chunkSize);
                //Handle the chunks are exactly dividing the full file case
                //Instead of producing empty last chunks it lowers the chunk count by one, after that the new last chunk is full sized one
                //Before: Chunk number = 4096, Last chunk size = 0 (Bytes read: 4096*1MB + 0) [Throws when reading/encrypting/decrypting due to 0 byte input/output]
                //After: Chunk number = 4095, Last chunk size = 1024 (Bytes read: 4095*1MB + 1MB)
                if (lastChunk == 0)
                {
                    chunkNumber--;
                    lastChunk = chunkSize;
                }
                chunkInformation = new EncryptionOptions.ChunkInformation(chunkSizeInMB, (ulong)chunkNumber, checked((uint)lastChunk));
            }
            short extraBytes = algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize;

            ulong fileSize = chunkInformation is null ? (ulong)(fileInfo.Length + extraBytes) : ((ulong)fileInfo.Length + ((ulong)extraBytes * chunkInformation.TotalChunks));
            return new EncryptionOptions.FileEncryptionOptions(1, fileName, fileSize, algorithm.ID, chunked, chunkInformation);
        }


        public SecureBuffer.SecureLargeBuffer EncryptAndPadFileEncryptionOptions(EncryptionOptions.FileEncryptionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            IVaultReader vaultReader = _session.VAULT_READER;
            short extraEncryptionDataSize = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[vaultReader.VaultEncryptionAlgorithm].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize;
            SecureBuffer.SecureLargeBuffer encryptionOptionsBytes = null!;
            SecureBuffer.SecureLargeBuffer paddedFileOptions = new SecureBuffer.SecureLargeBuffer(vaultReader.EncryptionOptionsSize - extraEncryptionDataSize);
            try
            {
                encryptionOptionsBytes = EncryptionOptions.FileEncryptionOptions.SerializeFileEncryptionOptions(options);
                if ((encryptionOptionsBytes.Length + extraEncryptionDataSize) > vaultReader.EncryptionOptionsSize)
                {
                    throw new VaultException(VaultException.ErrorContext.EncryptionOptions, VaultException.ErrorReason.FileNameTooLong);
                }
                encryptionOptionsBytes.AsSpan.CopyTo(paddedFileOptions.AsSpan);
            }
            finally
            {
                if (encryptionOptionsBytes is not null) encryptionOptionsBytes.Dispose();
            }
            SecureBuffer.SecureLargeBuffer encryptedFileOptions = null!;
            try
            {
                encryptedFileOptions = vaultReader.VaultEncryption(paddedFileOptions.AsMemory);
                return encryptedFileOptions;
            }
            catch (Exception)
            {
                if (encryptedFileOptions is not null) encryptedFileOptions.Dispose();
                throw;
            }
            finally
            {
                paddedFileOptions.Dispose();
            }
        }
        public EncryptionOptions.FileEncryptionOptions GetDecryptedFileEncryptionOptions(Stream vaultFS, long metadataOffset)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);
            ArgumentOutOfRangeException.ThrowIfNegative(metadataOffset);

            IVaultReader vaultReader = _session.VAULT_READER;
            SecureBuffer.SecureLargeBuffer decryptedMetadata = null!;
            EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = null!;
            try
            {
                decryptedMetadata = vaultReader.ReadAndDecryptData(vaultFS, metadataOffset, vaultReader.EncryptionOptionsSize);
                fileEncryptionOptions = EncryptionOptions.FileEncryptionOptionsReader.Deserialize(decryptedMetadata.AsSpan);
            }
            catch (Exception)
            {
                if (fileEncryptionOptions is not null) fileEncryptionOptions.Dispose();
                throw;
            }
            finally
            {
                if (decryptedMetadata is not null) decryptedMetadata.Dispose();
            }
            return fileEncryptionOptions;
        }
    }
}
