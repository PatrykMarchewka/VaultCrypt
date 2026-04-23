using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;
using VaultCrypt.Services;

namespace VaultCrypt
{
    public interface IVaultSession : IDisposable
    {
        /// <summary>
        /// Key used to encrypt/decrypt data
        /// </summary>
        public SecureBuffer.SecureKeyBuffer KEY { get; }
        /// <summary>
        /// Path to vault file
        /// </summary>
        public NormalizedPath VAULTPATH { get; }
        /// <summary>
        /// Dictionary holding information about encrypted files and offsets to their location
        /// </summary>
        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; }
        /// <summary>
        /// <see cref="IVaultReader"/> instance to properly read and write to vault
        /// </summary>
        public IVaultReader VAULT_READER { get; }
        /// <summary>
        /// Event to invoke when refreshing <see cref="ENCRYPTED_FILES"/> list
        /// </summary>
        public event Action? EncryptedFilesListUpdated;
        /// <summary>
        /// Sets <see cref="IVaultSession"/> fields
        /// </summary>
        /// <param name="vaultPath">Path to vault file</param>
        /// <param name="vaultReader">Reader instance to use when reading or writing to vault</param>
        /// <param name="password">Password to derive key from</param>
        /// <param name="salt">Salt used to derive key</param>
        /// <param name="iterations">Iterations number used when deriving key</param>
        public void CreateSession(NormalizedPath vaultPath, IVaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations);
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
        public ReadOnlySpan<byte> GetSlicedKey(byte keySize);
    }

    public class VaultSession : IVaultSession
    {

        public SecureBuffer.SecureKeyBuffer KEY { get; private set; }
        public NormalizedPath VAULTPATH { get; private set; }
        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; private set; }
        public IVaultReader VAULT_READER { get; private set; }

        public static VaultSession CurrentSession = new();
        public const byte NewestVaultVersion = 0;
        public event Action? EncryptedFilesListUpdated;

        /// <summary>
        /// Constructor initializing empty session values to avoid <see cref="NullReferenceException"/>
        /// </summary>
        private VaultSession()
        {
            this.KEY = new SecureBuffer.SecureKeyBuffer(PasswordHelper.KeySize);
            this.ENCRYPTED_FILES = new();
            this.VAULTPATH = NormalizedPath.From(string.Empty);
            this.VAULT_READER = null!;
        }

        public void CreateSession(NormalizedPath vaultPath, IVaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations)
        {
            PasswordHelper.DeriveKey(password, salt, iterations, this.KEY.AsSpan);
            this.VAULTPATH = vaultPath;
            this.ENCRYPTED_FILES.Clear();
            this.VAULT_READER = vaultReader;
        }

        public void RaiseEncryptedFileListUpdated()
        {
            this.EncryptedFilesListUpdated?.Invoke();
        }

        public ReadOnlySpan<byte> GetSlicedKey(byte keySize)
        {
            if (keySize > PasswordHelper.KeySize) throw new ArgumentOutOfRangeException("Requested bigger slice than the length of entire key");
            return this.KEY.AsSpan[..keySize];
        }

        /// <summary>
        /// Clears the sensitive vault session data from memory
        /// </summary>
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(this.KEY.AsSpan);
            this.ENCRYPTED_FILES.Clear();
            this.VAULTPATH = NormalizedPath.From(string.Empty);
            this.VAULT_READER = null!;
        }

    }

    public interface IVaultRegistry
    {
        /// <summary>
        /// Gets correct <see cref="IVaultReader"/>
        /// </summary>
        /// <param name="version">Version of the vault reader to get</param>
        /// <returns><see cref="IVaultReader"/> with specified version</returns>
        /// <exception cref="VaultException">Thrown when no reader for specified version can be found</exception>
        public IVaultReader GetVaultReader(byte version);
    }

    public class VaultRegistry : IVaultRegistry
    {
        public static VaultRegistry Current { get; private set; } = null!;
        private readonly Dictionary<byte, Lazy<IVaultReader>> _registry;
        

        public static VaultRegistry Initialize(IVaultSession session)
        {
            return Current = new VaultRegistry(session);
        }

        private VaultRegistry(IVaultSession session)
        {
            _registry = new()
            {
                {0, new Lazy<IVaultReader>(() => new VaultV0Reader(session)) }
            };
        }

        public IVaultReader GetVaultReader(byte version)
        {
            return _registry.TryGetValue(version, out var reader) ? reader.Value : throw new VaultException(VaultException.ErrorContext.VaultSession, VaultException.ErrorReason.NoReader);
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
        public SecureBuffer.SecureLargeBuffer ReadSalt(Stream stream);

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
        public SecureBuffer.SecureLargeBuffer PrepareVaultHeader(ReadOnlySpan<byte> salt, int iterations);

        /// <summary>
        /// Reads and decrypts metadata offsets
        /// </summary>
        /// <param name="stream">Stream to vault file to read from</param>
        /// <returns>Array of metadata offsets</returns>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="stream"/> is set to null value</exception>
        public long[] ReadMetadataOffsets(Stream stream);

        /// <summary>
        /// Adds <paramref name="newOffset"/> to offsets list and saves it back encrypted to <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Vault file to read and write to</param>
        /// <param name="newOffset">New offset to add</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="newOffset"/> is set to negative or zero value</exception>
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
        public void SaveMetadataOffsets(Stream stream, long[] offsets);

        /// <summary>
        /// Reads and decrypts <paramref name="length"/> bytes from <paramref name="stream"/> at <paramref name="offset"/> offset using <see cref="VaultEncryptionAlgorithm"/>
        /// </summary>
        /// <param name="stream">Vault file to read from</param>
        /// <param name="offset">Offset to position in the vault</param>
        /// <param name="length">Number of bytes to read</param>
        /// <returns>Decrypted information</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="offset"/> is set to negative value or <paramref name="length"/> is set to negative or zero value</exception>
        public SecureBuffer.SecureLargeBuffer ReadAndDecryptData(Stream stream, long offset, int length);

        /// <summary>
        /// Encrypts <paramref name="data"/> using <see cref="VaultEncryptionAlgorithm"/>
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns>Encrypted information</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="data"/> is empty</exception>
        public SecureBuffer.SecureLargeBuffer VaultEncryption(ReadOnlySpan<byte> data);
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

        private readonly IVaultSession _session;

        protected VaultReader(IVaultSession session)
        {
            this._session = session;
        }

        #region Vault header
        public SecureBuffer.SecureLargeBuffer ReadSalt(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            SecureBuffer.SecureLargeBuffer salt = new SecureBuffer.SecureLargeBuffer(SaltSize);
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
        public SecureBuffer.SecureLargeBuffer PrepareVaultHeader(ReadOnlySpan<byte> salt, int iterations)
        {
            if (salt.IsEmpty) throw new ArgumentException("Provided empty salt", nameof(salt));
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);

            SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(1 + SaltSize + sizeof(int));
            try
            {
                buffer.AsSpan[0] = Version;
                salt.CopyTo(buffer.AsSpan.Slice(1));
                BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan.Slice(1 + SaltSize, sizeof(int)), iterations);
                return buffer;
            }
            catch(Exception)
            {
                buffer.Dispose();
                throw;
            }
        }

        
        #endregion

        #region Metadata offsets
        public long[] ReadMetadataOffsets(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            SecureBuffer.SecureLargeBuffer decrypted = null!;
            long[] offsets = null!;
            try
            {
                decrypted = ReadMetadataOffsetsBytes(stream);
                ushort fileCount = BinaryPrimitives.ReadUInt16LittleEndian(decrypted.AsSpan);

                offsets = new long[fileCount];
                for (int i = 0; i < fileCount; i++)
                {
                    int readOffset = sizeof(ushort) + (i * sizeof(long));
                    offsets[i] = BinaryPrimitives.ReadInt64LittleEndian(decrypted.AsSpan.Slice(readOffset, sizeof(long)));
                }
                return offsets;
            }
            catch (Exception)
            {
                if (offsets is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(offsets.AsSpan()));
                throw;
            }
            finally
            {
                decrypted?.Dispose();
            }

        }

        private SecureBuffer.SecureLargeBuffer ReadMetadataOffsetsBytes(Stream stream)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(int), SeekOrigin.Begin);

            //Example: extra data (28 bytes for AES) + number of files (ushort) + max metadata offsets size
            int bufferSize = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize + sizeof(ushort) + MetadataOffsetsSize;
            using (SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(bufferSize))
            {
                stream.ReadExactly(buffer.AsSpan);
                return VaultDecryption(buffer.AsSpan);
            }
        }

        public void AddAndSaveMetadataOffsets(Stream stream, long newOffset)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(newOffset);

            long[] oldOffsets = null!;
            long[] newOffsets = null!;
            try
            {
                oldOffsets = ReadMetadataOffsets(stream);
                if (((oldOffsets.Length + 1) * 8) > MetadataOffsetsSize)
                {
                    throw new VaultException(VaultException.ErrorContext.VaultSession, VaultException.ErrorReason.FullVault);
                }
                newOffsets = new long[oldOffsets.Length + 1];
                oldOffsets.AsSpan().CopyTo(newOffsets);
                newOffsets[oldOffsets.Length] = newOffset;
                SaveMetadataOffsets(stream, newOffsets);
            }
            finally
            {
                if (oldOffsets is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(oldOffsets.AsSpan()));
                if (newOffsets is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(newOffsets.AsSpan()));
            }

        }

        public void RemoveAndSaveMetadataOffsets(Stream stream, ushort itemIndex)
        {
            ArgumentNullException.ThrowIfNull(stream);

            long[] oldOffsets = null!;
            long[] newOffsets = null!;
            try
            {
                oldOffsets = ReadMetadataOffsets(stream);
                newOffsets = oldOffsets.Where((offset, index) => index != itemIndex).ToArray();
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(oldOffsets.AsSpan()));
                SaveMetadataOffsets(stream, newOffsets);
            }
            finally
            {
                if (oldOffsets is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(oldOffsets.AsSpan()));
                if (newOffsets is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(newOffsets.AsSpan()));
            }
        }

        private SecureBuffer.SecureLargeBuffer PrepareMetadataOffsets(long[] offsets)
        {
            long[] distinctOffsets = [.. offsets.Distinct()];
            try
            {
                SecureBuffer.SecureLargeBuffer offsetsBuffer = new SecureBuffer.SecureLargeBuffer(sizeof(ushort) + (distinctOffsets.Length * sizeof(long)));
                BinaryPrimitives.WriteUInt16LittleEndian(offsetsBuffer.AsSpan, (ushort)distinctOffsets.Length);
                MemoryMarshal.AsBytes(distinctOffsets.AsSpan()).CopyTo(offsetsBuffer.AsSpan.Slice(sizeof(ushort)));
                return offsetsBuffer;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(distinctOffsets.AsSpan()));
            }
            
        }

        /// <summary>
        /// Pads supplied <paramref name="metadataOffsets"/> to <see cref="MetadataOffsetsSize"/> and encrypts the entire collection
        /// </summary>
        /// <param name="metadataOffsets"></param>
        /// <returns></returns>
        private SecureBuffer.SecureLargeBuffer PadMetadataOffsetsAndEncrypt(SecureBuffer.SecureLargeBuffer metadataOffsets)
        {
            SecureBuffer.SecureLargeBuffer paddedMetadataOffsets = new SecureBuffer.SecureLargeBuffer(sizeof(ushort) + MetadataOffsetsSize); //2 bytes ushort for number of currently attached offsets
            SecureBuffer.SecureLargeBuffer encryptedMetadataOffsets = null!;
            try
            {
                metadataOffsets.AsSpan.CopyTo(paddedMetadataOffsets.AsSpan);
                encryptedMetadataOffsets = VaultEncryption(paddedMetadataOffsets.AsSpan);
                return encryptedMetadataOffsets;
            }
            catch (Exception)
            {
                encryptedMetadataOffsets?.Dispose();
                throw;
            }
            finally
            {
                paddedMetadataOffsets.Dispose();
            }
        }

        private void WriteMetadataOffsets(Stream stream, ReadOnlySpan<byte> encryptedMetadataOffsets)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(int), SeekOrigin.Begin); //1 byte for version + bytes for salt + 4 bytes for iterations
            stream.Write(encryptedMetadataOffsets);
        }

        public void SaveMetadataOffsets(Stream stream, long[] offsets)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentNullException.ThrowIfNull(offsets);

            SecureBuffer.SecureLargeBuffer offsetsBuffer = null!;
            SecureBuffer.SecureLargeBuffer encryptedMetadataOffsets = null!;
            try
            {
                offsetsBuffer = PrepareMetadataOffsets(offsets);
                encryptedMetadataOffsets = PadMetadataOffsetsAndEncrypt(offsetsBuffer);
                WriteMetadataOffsets(stream, encryptedMetadataOffsets.AsSpan);
            }
            finally
            {
                offsetsBuffer?.Dispose();
                encryptedMetadataOffsets?.Dispose();
            }
        }
        #endregion

        public SecureBuffer.SecureLargeBuffer ReadAndDecryptData(Stream stream, long offset, int length)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

            using (SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(length))
            {
                stream.Seek(offset, SeekOrigin.Begin);
                stream.ReadExactly(buffer.AsSpan);
                return VaultDecryption(buffer.AsSpan);
            }
        }

        public SecureBuffer.SecureLargeBuffer VaultEncryption(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            var provider = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider();
            return provider.EncryptionAlgorithm.EncryptBytes(data, _session.GetSlicedKey(provider.KeySize));
        }

        private SecureBuffer.SecureLargeBuffer VaultDecryption(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            var provider = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider();
            if (data.Length < provider.EncryptionAlgorithm.ExtraEncryptionDataSize) throw new ArgumentException("Provided data is too short", nameof(data));

            return provider.EncryptionAlgorithm.DecryptBytes(data, _session.GetSlicedKey(provider.KeySize));
        }
    }


    public class VaultV0Reader : VaultReader
    {
        public VaultV0Reader(IVaultSession session) : base(session) { }

        public override byte Version => 0;
        public override byte VaultEncryptionAlgorithm => EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.ID;
    }








}
