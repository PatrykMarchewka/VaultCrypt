using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;


namespace VaultCrypt
{
    public interface IVaultSession : IDisposable
    {
        /// <summary>
        /// Version of the vault attached to this session instance
        /// </summary>
        public byte VERSION { get; }
        /// <summary>
        /// Key used to encrypt/decrypt data
        /// </summary>
        public ISecureBuffer KEY { get; }
        /// <summary>
        /// Path to vault file
        /// </summary>
        public NormalizedPath VAULTPATH { get; }
        /// <summary>
        /// Dictionary holding information about encrypted files and offsets to their location
        /// </summary>
        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; }
        /// <summary>
        /// Event to invoke when refreshing <see cref="ENCRYPTED_FILES"/> list
        /// </summary>
        public event Action? EncryptedFilesListUpdated;
        /// <summary>
        /// Sets this session fields
        /// </summary>
        /// <param name="version">Version of the vault</param>
        /// <param name="vaultPath">Path to vault file</param>
        /// <param name="password">Password to derive key from</param>
        /// <param name="salt">Salt used to derive key from</param>
        /// <param name="iterations">Number of iterations used when deriving key</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="vaultPath"/> is set to null</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="vaultPath"/> is empty or set to whitespace only characters, or when <paramref name="password"/> is empty, or when <paramref name="salt"/> is empty</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="iterations"/> is set to negative value or zero</exception>
        public void CreateSession(byte version, NormalizedPath vaultPath, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations);
        /// <summary>
        /// Raises <see cref="EncryptedFilesListUpdated"/>
        /// </summary>
        public void RaiseEncryptedFileListUpdated();
        /// <summary>
        /// Slices <see cref="KEY"/> into desired <paramref name="keySize"/>
        /// </summary>
        /// <param name="keySize">Requested size of key</param>
        /// <returns>Sliced key with length equal to <paramref name="keySize"/></returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when requested a slice that is bigger than entire key</exception>
        public ReadOnlySpan<byte> GetSlicedKey(int keySize);
    }

    public class VaultSession : IVaultSession
    {
        public byte VERSION { get; private set; }
        public ISecureBuffer KEY { get; private set; }
        public NormalizedPath VAULTPATH { get; private set; }
        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; private set; }


        public static VaultSession CurrentSession = new();
        public const byte NewestVaultVersion = 0;
        public event Action? EncryptedFilesListUpdated;

        /// <summary>
        /// Constructor initializing empty session values to avoid <see cref="NullReferenceException"/>
        /// </summary>
        private VaultSession()
        {
            this.VERSION = 0;
            this.KEY = SecureBuffer.Create(PasswordHelper.KeySize);
            this.ENCRYPTED_FILES = new();
            this.VAULTPATH = NormalizedPath.From(string.Empty);
        }

        public void CreateSession(byte version, NormalizedPath vaultPath, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
            if (password.IsEmpty) throw new ArgumentException("Provided empty password");
            if (salt.IsEmpty) throw new ArgumentException("Provided empty salt");
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);

            this.VERSION = version;
            PasswordHelper.DeriveKey(password, salt, iterations, this.KEY.AsSpan);
            this.VAULTPATH = vaultPath;
            this.ENCRYPTED_FILES.Clear();
        }

        public void RaiseEncryptedFileListUpdated()
        {
            this.EncryptedFilesListUpdated?.Invoke();
        }

        public ReadOnlySpan<byte> GetSlicedKey(int keySize)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keySize);
            if (keySize > PasswordHelper.KeySize) throw new ArgumentOutOfRangeException("Requested bigger slice than the length of entire key");
            return this.KEY.AsSpan[..keySize];
        }

        /// <summary>
        /// Clears the sensitive vault session data from memory
        /// </summary>
        public void Dispose()
        {
            this.VERSION = 0;
            CryptographicOperations.ZeroMemory(this.KEY.AsSpan);
            this.ENCRYPTED_FILES.Clear();
            this.VAULTPATH = NormalizedPath.From(string.Empty);
        }

    }

    public static class VaultRegistry
    {
        //Recreates the entire dictionary, because of Func<> only the requested reader gets created and not all of them
        private static Dictionary<byte, Func<IVaultReader>> _createRegistry()
        {
            return new()
            {
                {0, new Func<IVaultReader>(() => new VaultV0Reader()) }
            };
        }

        /// <summary>
        /// Gets correct <see cref="IVaultReader"/> for <see cref="VaultSession.CurrentSession"/>
        /// </summary>
        /// <param name="version">Version of the vault to get reader for</param>
        /// <returns><see cref="IVaultReader"/> for specified vault version</returns>
        /// <exception cref="VaultException">Thrown when no reader for specified version can be found</exception>
        public static IVaultReader GetVaultReader(byte version)
        {
            return _createRegistry().TryGetValue(version, out var reader) ? reader() : throw new VaultOperationException(VaultException.ErrorReason.NoReader);
        }
    }

    public interface IVaultReader
    {
        /// <summary>
        /// Numeric version of the vault
        /// </summary>
        public byte Version { get; }
        /// <summary>
        /// Encryption algorithm ID to use for vault metadata
        /// </summary>
        public byte VaultEncryptionAlgorithm { get; }
        /// <summary>
        /// Size in bytes of the salt
        /// </summary>
        public ushort SaltSize { get; }
        /// <summary>
        /// Size of already encrypted EncryptionOptions
        /// </summary>
        public ushort EncryptionOptionsSize { get; }
        /// <summary>
        /// Size of metadata offsets collection before encryption
        /// </summary>
        public ushort MetadataOffsetsSize { get; }
        /// <summary>
        /// Full size of vault header
        /// </summary>
        public ushort HeaderSize { get; }



        /// <summary>
        /// Reads salt from vault header
        /// </summary>
        /// <param name="stream">Stream to vault file to read from</param>
        /// <returns>Salt read from <paramref name="stream"/></returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is null</exception>
        public ISecureBuffer ReadSalt(Stream stream);

        /// <summary>
        /// Reads password iteration number from vault header
        /// </summary>
        /// <param name="stream">Stream to vault file to read from</param>
        /// <returns>Number of iterations to get correct key from password</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is null</exception>
        public int ReadIterationsNumber(Stream stream);

        /// <summary>
        /// Combines <see cref="Version"/>, <paramref name="salt"/> and <paramref name="iterations"/> into one array
        /// </summary>
        /// <param name="salt">Salt value to include</param>
        /// <param name="iterations">Iterations number to include</param>
        /// <returns>Array containing <see cref="Version"/>, <paramref name="salt"/> and <paramref name="iterations"/></returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="salt"/> is empty</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="iterations"/> is set to negative value or zero</exception>
        public ISecureBuffer PrepareVaultHeader(ReadOnlySpan<byte> salt, int iterations);

        /// <summary>
        /// Encrypts <paramref name="data"/> using <see cref="VaultEncryptionAlgorithm"/>
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns>Secure buffer holding encrypted information</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="data"/> is empty</exception>
        public ISecureBuffer VaultEncryption(ReadOnlySpan<byte> data);

        /// <summary>
        /// Reads and decrypts metadata offsets
        /// </summary>
        /// <param name="stream">Stream to vault file to read from</param>
        /// <returns>Secure buffer holding decrypted metadata offsets</returns>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="stream"/> is set to null value</exception>
        public ISecureBuffer ReadMetadataOffsets(Stream stream);

        /// <summary>
        /// Adds <paramref name="newOffset"/> to offsets list and saves it back encrypted to <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Vault file to read and write to</param>
        /// <param name="newOffset">New offset to add</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="newOffset"/> is set to negative or zero value</exception>
        /// <exception cref="VaultOperationException">Thrown when vault is full and can't add any new files</exception>
        public void AddAndSaveMetadataOffsets(Stream stream, long newOffset);

        /// <summary>
        /// Removes offset at <paramref name="itemIndex"/> from offsets list and saves it back encrypted to <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Vault file to read and write to</param>
        /// <param name="itemIndex">Zero based index to remove</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        public void RemoveAndSaveMetadataOffsets(Stream stream, ushort itemIndex);

        /// <summary>
        /// Encrypts provided <paramref name="offsets"/> and replaces current metadata offsets in <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Vault file to read and write to</param>
        /// <param name="offsets">Metadata offsets to save</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> or <paramref name="offsets"/> is set to null</exception>
        public void SaveMetadataOffsets(Stream stream, ISecureBuffer offsets);

        /// <summary>
        /// Reads and decrypts <paramref name="length"/> bytes from <paramref name="stream"/> at <paramref name="offset"/> offset using <see cref="VaultEncryptionAlgorithm"/>
        /// </summary>
        /// <param name="stream">Vault file to read from</param>
        /// <param name="offset">Offset to position in the vault</param>
        /// <param name="length">Number of bytes to read</param>
        /// <returns>Decrypted information</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="offset"/> is set to negative value or <paramref name="length"/> is set to negative or zero value</exception>
        public ISecureBuffer ReadAndDecryptData(Stream stream, long offset, int length);
    }

    //For new versions append the additional data at the end
    //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number +  MetadataOffsetsSize (4KB (4096 bytes))]...
    public abstract class VaultReader : IVaultReader
    {
        /// <summary>
        /// Version of the vault
        /// </summary>
        public abstract byte Version { get; }
        /// <summary>
        /// ID of encryption algoritm used to encrypt/decrypt vault metadata
        /// </summary>
        public abstract byte VaultEncryptionAlgorithm { get; }

        /// <summary>
        /// Length of the salt in bytes
        /// </summary>
        public virtual ushort SaltSize => 32;

        /// <summary>
        /// Length of the individual file encryption options after encryption in bytes
        /// </summary>
        public virtual ushort EncryptionOptionsSize => 1024;

        /// <summary>
        /// Length of metadata offsets in bytes
        /// </summary>
        public virtual ushort MetadataOffsetsSize => 4096;

        /// <summary>
        /// Length of entire vault header in bytes
        /// </summary>
        public virtual ushort HeaderSize => (ushort)(1 + SaltSize + sizeof(int) + EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize + sizeof(ushort) + MetadataOffsetsSize);

        #region Vault header
        public ISecureBuffer ReadSalt(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            ISecureBuffer salt = SecureBuffer.Create(SaltSize);
            try
            {
                stream.Seek(1, SeekOrigin.Begin);
                stream.ReadExactly(salt.AsSpan);
                return salt;
            }
            catch (Exception)
            {
                salt.Dispose();
                throw;
            }
        }
        public int ReadIterationsNumber(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            Span<byte> iterationBytes = stackalloc byte[sizeof(int)];
            try
            {
                stream.Seek(1 + SaltSize, SeekOrigin.Begin);
                stream.ReadExactly(iterationBytes);
                return BinaryPrimitives.ReadInt32LittleEndian(iterationBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(iterationBytes);
            }
        }
        public ISecureBuffer PrepareVaultHeader(ReadOnlySpan<byte> salt, int iterations)
        {
            if (salt.IsEmpty) throw new ArgumentException("Provided empty salt", nameof(salt));
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);

            ISecureBuffer buffer = SecureBuffer.Create(1 + SaltSize + sizeof(int));
            try
            {
                buffer.AsSpan[0] = Version;
                salt.CopyTo(buffer.AsSpan.Slice(1));
                BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan.Slice(1 + SaltSize, sizeof(int)), iterations);
                return buffer;
            }
            catch (Exception)
            {
                buffer.Dispose();
                throw;
            }
        }
        #endregion

        #region Metadata offsets
        public ISecureBuffer VaultEncryption(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            var provider = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider();
            return provider.EncryptionAlgorithm.EncryptBytes(data, VaultSession.CurrentSession.GetSlicedKey(provider.KeySize));
        }

        private ISecureBuffer VaultDecryption(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            var provider = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider();
            if (data.Length < provider.EncryptionAlgorithm.ExtraEncryptionDataSize) throw new ArgumentException("Provided data is too short", nameof(data));

            return provider.EncryptionAlgorithm.DecryptBytes(data, VaultSession.CurrentSession.GetSlicedKey(provider.KeySize));
        }

        public ISecureBuffer ReadAndDecryptData(Stream stream, long offset, int length)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

            using (ISecureBuffer buffer = SecureBuffer.Create(length))
            {
                stream.Seek(offset, SeekOrigin.Begin);
                stream.ReadExactly(buffer.AsSpan);
                return VaultDecryption(buffer.AsSpan);
            }
        }

        //Reads and decrypts metadata offsets as raw bytes
        private ISecureBuffer ReadMetadataOffsetsBytes(Stream stream)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(int), SeekOrigin.Begin);
            //Example: extra data (28 bytes for AES) + number of files (ushort) + max metadata offsets size
            int bufferSize = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize + sizeof(ushort) + MetadataOffsetsSize;
            using (ISecureBuffer buffer = SecureBuffer.Create(bufferSize))
            {
                stream.ReadExactly(buffer.AsSpan);
                return VaultDecryption(buffer.AsSpan);
            }
        }

        public ISecureBuffer ReadMetadataOffsets(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            using (ISecureBuffer decryptedOffsetBytes = ReadMetadataOffsetsBytes(stream))
            {
                SecureBufferReadWrite.SecureBufferReader decryptedOffsetsReader = new SecureBufferReadWrite.SecureBufferReader(decryptedOffsetBytes);
                ushort fileCount = decryptedOffsetsReader.ReadUInt16();
                ISecureBuffer decryptedBuffer = SecureBuffer.Create(fileCount * sizeof(long));
                SecureBufferReadWrite.SecureBufferWriter decryptedBufferWriter = new SecureBufferReadWrite.SecureBufferWriter(decryptedBuffer);
                for (int i = 0; i < fileCount; i++)
                {
                    using (ISecureBuffer readOffset = decryptedOffsetsReader.ReadBytes(sizeof(long)))
                    {
                        decryptedBufferWriter.WriteSpan(readOffset.AsSpan);
                    }
                }
                return decryptedBuffer;
            }
        }

        // Attaches number of offsets
        private ISecureBuffer PrepareMetadataOffsets(ISecureBuffer offsets)
        {
            ArgumentNullException.ThrowIfNull(offsets);
            if (offsets.AsSpan.IsEmpty) throw new ArgumentException("Provided no offsets", nameof(offsets));

            ISecureBuffer buffer = SecureBuffer.Create(sizeof(ushort) + offsets.AsSpan.Length);
            ushort offsetsNumber = checked((ushort)(offsets.AsSpan.Length / sizeof(long)));
            SpanWriter writer = new SpanWriter(buffer.AsSpan);
            writer.WriteUInt16(offsetsNumber);
            writer.WriteSpan(offsets.AsSpan);
            return buffer;
        }

        //Pads supplied metadataOffsets to match session's metadataoffset size and encrypts the entire collection
        private ISecureBuffer PadMetadataOffsetsAndEncrypt(ISecureBuffer metadataOffsets)
        {
            ArgumentNullException.ThrowIfNull(metadataOffsets);
            if (metadataOffsets.AsSpan.IsEmpty) throw new ArgumentException("Provided no offsets", nameof(metadataOffsets));
            if (metadataOffsets.AsSpan.Length > MetadataOffsetsSize) throw new ArgumentOutOfRangeException("Provided offsets length is too big");


            using (ISecureBuffer paddedMetadataOffsets = SecureBuffer.Create(sizeof(ushort) + MetadataOffsetsSize)) //2 bytes ushort for number of currently attached offsets
            {
                metadataOffsets.AsSpan.CopyTo(paddedMetadataOffsets.AsSpan);
                return VaultEncryption(paddedMetadataOffsets.AsSpan);
            }
        }

        //Writes metadataoffsets to correct point in stream
        private void WriteMetadataOffsets(Stream stream, ReadOnlySpan<byte> encryptedMetadataOffsets)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(int), SeekOrigin.Begin); //1 byte for version + bytes for salt + 4 bytes for iterations
            stream.Write(encryptedMetadataOffsets);
        }

        public void SaveMetadataOffsets(Stream stream, ISecureBuffer offsets)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentNullException.ThrowIfNull(offsets);
            
            using (ISecureBuffer preparedOffsets = PrepareMetadataOffsets(offsets))
            {
                using (ISecureBuffer encryptedMetadataOffsets = PadMetadataOffsetsAndEncrypt(preparedOffsets))
                {
                    WriteMetadataOffsets(stream, encryptedMetadataOffsets.AsSpan);
                }
            }
        }

        public void AddAndSaveMetadataOffsets(Stream stream, long newOffset)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentOutOfRangeException.ThrowIfLessThan(newOffset, this.HeaderSize); //Prevent adding new offset belonging to header information

            using (ISecureBuffer oldOffsets = ReadMetadataOffsets(stream))
            {
                int newOffsetsSize = oldOffsets.AsSpan.Length + sizeof(long);
                if (newOffsetsSize > MetadataOffsetsSize)
                {
                    throw new VaultOperationException(VaultException.ErrorReason.FullVault);
                }
                using (ISecureBuffer newOffsets = SecureBuffer.Create(newOffsetsSize))
                {
                    oldOffsets.AsSpan.CopyTo(newOffsets.AsSpan);
                    BinaryPrimitives.WriteInt64LittleEndian(newOffsets.AsSpan[^sizeof(long)..], newOffset);
                    SaveMetadataOffsets(stream, newOffsets);
                }
            }
        }

        public void RemoveAndSaveMetadataOffsets(Stream stream, ushort itemIndex)
        {
            ArgumentNullException.ThrowIfNull(stream);

            using (ISecureBuffer oldOffsets = ReadMetadataOffsets(stream))
            {
                using (ISecureBuffer newOffsets = SecureBuffer.Create(oldOffsets.AsSpan.Length - sizeof(long)))
                {
                    int removedOffset = sizeof(long) * itemIndex;
                    var leftSide = oldOffsets.AsSpan[..removedOffset];
                    var rightSide = oldOffsets.AsSpan[(removedOffset + sizeof(long))..];

                    leftSide.CopyTo(newOffsets.AsSpan);
                    rightSide.CopyTo(newOffsets.AsSpan[leftSide.Length..]);

                    SaveMetadataOffsets(stream, newOffsets);
                }
            }
        }
        #endregion
    }


    public class VaultV0Reader : VaultReader
    {
        public VaultV0Reader() : base() { }

        public override byte Version => 0;
        public override byte VaultEncryptionAlgorithm => EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.ID;
    }








}
