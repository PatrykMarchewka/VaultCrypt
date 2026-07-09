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
        /// <summary>
        /// Converts provided information into <see cref="EncryptionOptions.FileEncryptionOptions"/>
        /// </summary>
        /// <param name="fileInfo">Information about file</param>
        /// <param name="algorithm">Algorithm to use when encrypting or decrypting this file</param>
        /// <param name="chunkSizeInMB">Maximum size of each chunk in megabytes, if file size is lower than chunk size then it gets encrypted in one singular chunk</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="fileInfo"/> or <paramref name="algorithm"/> is set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="chunkSizeInMB"/> value is set to zero</exception>
        public EncryptionOptions.FileEncryptionOptions PrepareEncryptionOptions(FileInfo fileInfo, EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, ushort chunkSizeInMB);
        /// <summary>
        /// Pads <paramref name="options"/> and encrypts it ensuring final output length is exactly <see cref="IVaultReader.EncryptionOptionsSize"/> bytes
        /// </summary>
        /// <param name="options">Options to pad and then encrypt</param>
        /// <returns>Encrypted and padded options</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is set to null</exception>
        /// <exception cref="VaultCrypt.Exceptions.VaultEncryptionOptionsOperationException">Thrown when encrypted <see cref="EncryptionOptions.FileEncryptionOptions"/> would be too big to fit in the vault due to file name being too long</exception>
        public ISecureBuffer PadAndEncryptFileEncryptionOptions(EncryptionOptions.FileEncryptionOptions options);
        /// <summary>
        /// Gets encrypted options at <paramref name="metadataOffset"/> from vault and decrypts it
        /// </summary>
        /// <param name="vaultFS">Vault to read from</param>
        /// <param name="metadataOffset">Offset at which to start reading</param>
        /// <returns>Decrypted options</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="vaultFS"/> is set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="metadataOffset"/> points to vault header or is set to negative value</exception>
        public EncryptionOptions.FileEncryptionOptions GetDecryptedFileEncryptionOptions(Stream vaultFS, long metadataOffset);
    }

    public class EncryptionOptionsService : IEncryptionOptionsService
    {
        private IVaultSession _session => VaultSession.CurrentSession;

        public EncryptionOptions.FileEncryptionOptions PrepareEncryptionOptions(FileInfo fileInfo, EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, ushort chunkSizeInMB)
        {
            ArgumentNullException.ThrowIfNull(fileInfo);
            ArgumentNullException.ThrowIfNull(algorithm);
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);

            ulong fileLength = (ulong)fileInfo.Length;
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

            ulong encryptedFileSize = chunkInformation is null ? (fileLength + (ulong)extraBytes) : ((ulong)fileLength + ((ulong)extraBytes * chunkInformation.TotalChunks));
            return new EncryptionOptions.FileEncryptionOptions(1, fileInfo.Name, encryptedFileSize, algorithm.ID, chunked, chunkInformation);
        }


        public ISecureBuffer PadAndEncryptFileEncryptionOptions(EncryptionOptions.FileEncryptionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            IVaultReader vaultReader = VaultRegistry.GetVaultReader(_session.VERSION);
            short extraEncryptionDataSize = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[vaultReader.VaultEncryptionAlgorithm].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize;
            using (ISecureBuffer paddedFileOptions = SecureBuffer.Create(vaultReader.EncryptionOptionsSize - extraEncryptionDataSize))
            {
                using (ISecureBuffer encryptionOptionsBytes = EncryptionOptions.FileEncryptionOptions.SerializeFileEncryptionOptions(options))
                {
                    if ((encryptionOptionsBytes.AsSpan.Length + extraEncryptionDataSize) > vaultReader.EncryptionOptionsSize)
                    {
                        throw new VaultEncryptionOptionsOperationException(VaultException.ErrorReason.FileNameTooLong);
                    }
                    encryptionOptionsBytes.AsSpan.CopyTo(paddedFileOptions.AsSpan);
                }

                return vaultReader.VaultEncryption(paddedFileOptions.AsSpan);
            }
        }
        public EncryptionOptions.FileEncryptionOptions GetDecryptedFileEncryptionOptions(Stream vaultFS, long metadataOffset)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);
            IVaultReader vaultReader = VaultRegistry.GetVaultReader(_session.VERSION);
            ArgumentOutOfRangeException.ThrowIfLessThan(metadataOffset, vaultReader.HeaderSize); //First FileEncryptionOptions must always be after header

            using (ISecureBuffer decryptedMetadata = vaultReader.ReadAndDecryptData(vaultFS, metadataOffset, vaultReader.EncryptionOptionsSize))
            {
                return EncryptionOptions.FileEncryptionOptionsReader.Deserialize(decryptedMetadata);
            }
        }
    }
}
