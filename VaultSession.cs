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
    public interface IVaultSession
    {
        public SecureBuffer.SecureKeyBuffer KEY { get; }
        public NormalizedPath VAULTPATH { get; }
        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; }
        public IVaultReader VAULT_READER { get; }
        public event Action? EncryptedFilesListUpdated;
        public void CreateSession(NormalizedPath vaultPath, IVaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations);
        public void RasiseEncryptedFileListUpdated();
        public ReadOnlySpan<byte> GetSlicedKey(byte keySize);
        public void Dispose();
    }

    public class VaultSession : IDisposable, IVaultSession
    {

        public SecureBuffer.SecureKeyBuffer KEY { get; private set; }
        public NormalizedPath VAULTPATH { get; private set; }
        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; private set; }
        public IVaultReader VAULT_READER { get; private set; }

        public static VaultSession CurrentSession = new();
        public const byte NewestVaultVersion = 0;
        public event Action? EncryptedFilesListUpdated;

        /// <summary>
        /// Empty constructor initializing empty session to avoid NullReferenceException
        /// </summary>
        private VaultSession()
        {
            KEY = new SecureBuffer.SecureKeyBuffer(PasswordHelper.KeySize);
            ENCRYPTED_FILES = new();
            VAULTPATH = NormalizedPath.From(string.Empty);
            VAULT_READER = null!;
        }

        public void CreateSession(NormalizedPath vaultPath, IVaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations)
        {
            PasswordHelper.DeriveKey(password, salt, iterations, this.KEY.AsSpan);
            this.VAULTPATH = vaultPath;
            this.ENCRYPTED_FILES.Clear();
            this.VAULT_READER = vaultReader;
        }

        public void RasiseEncryptedFileListUpdated()
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
            ENCRYPTED_FILES.Clear();
            VAULTPATH = NormalizedPath.From(string.Empty);
            VAULT_READER = null!;
        }

    }

    public interface IVaultRegistry
    {
        public IVaultReader GetVaultReader(byte version);
    }

    public class VaultRegistry : IVaultRegistry
    {
        public static VaultRegistry Current { get; private set; } = null!;
        private static Dictionary<byte, Lazy<IVaultReader>> registry = null!;
        

        public static VaultRegistry Initialize(IVaultSession session)
        {
            return Current = new VaultRegistry(session);
        }
        private VaultRegistry(IVaultSession session)
        {
            registry = new()
            {
                {0, new Lazy<IVaultReader>(() => new VaultV0Reader(session)) }
            };
        }

        public IVaultReader GetVaultReader(byte version)
        {
            return registry.TryGetValue(version, out var reader) ? reader.Value : throw new VaultException(VaultException.ErrorContext.VaultSession, VaultException.ErrorReason.NoReader);
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
        /// <returns>Salt in bytes</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is null</exception>
        public byte[] ReadSalt(Stream stream);

        /// <summary>
        /// Reads password iteration number from vault header
        /// </summary>
        /// <param name="stream">Stream to vault file to read from</param>
        /// <returns>Number of iterations to get correct key from password</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is null</exception>
        public int ReadIterationsNumber(Stream stream);

        /// <summary>
        /// Combines <see cref="Version"/>, <paramref name="salt"/> and <paramref name="iterations"/> into one byte array
        /// </summary>
        /// <param name="salt">Salt value to include</param>
        /// <param name="iterations">Iterations number to include</param>
        /// <returns>Array containing <see cref="Version"/>, <paramref name="salt"/> and <paramref name="iterations"/></returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="salt"/> is null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="iterations"/> is set to negative value or zero</exception>
        public byte[] PrepareVaultHeader(byte[] salt, int iterations);

        /// <summary>
        /// Reads metadata offsets from vault header
        /// </summary>
        /// <param name="stream">Stream to vault file to read from</param>
        /// <returns>Array of offsets</returns>
        public long[] ReadMetadataOffsets(Stream stream);

        /// <summary>
        /// Adds <paramref name="newOffset"/> to offsets list and saves it back to the <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Vault file to read and write to</param>
        /// <param name="newOffset">New offset to add</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="newOffset"/> is set to negative or zero</exception>
        public void AddAndSaveMetadataOffsets(Stream stream, long newOffset);

        /// <summary>
        /// Removes offset at <paramref name="itemIndex"/> from offsets list and saves it back to the <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Vault file to read and write to</param>
        /// <param name="itemIndex">Index to remove</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        public void RemoveAndSaveMetadataOffsets(Stream stream, ushort itemIndex);

        /// <summary>
        /// Saves provided <paramref name="offsets"/> to the <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Vault file to write to</param>
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
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="offset"/> or <paramref name="length"/> is negative or zero</exception>
        public SecureBuffer.SecureLargeBuffer ReadAndDecryptData(Stream stream, long offset, int length);

        /// <summary>
        /// Encrypts <paramref name="data"/> using <see cref="VaultEncryptionAlgorithm"/>
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns>Encrypted information</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="data"/> is empty</exception>
        public SecureBuffer.SecureLargeBuffer VaultEncryption(ReadOnlyMemory<byte> data);

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
        /// <summary>
        /// Reads salt from vault header
        /// </summary>
        /// <param name="stream">Stream to read from</param>
        /// <returns>Salt</returns>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="stream"/> is set to null value</exception>
        public byte[] ReadSalt(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            byte[] salt = new byte[SaltSize];
            try
            {
                stream.Seek(1, SeekOrigin.Begin);
                stream.ReadExactly(salt);
                return salt;
            }
            catch (Exception)
            {
                CryptographicOperations.ZeroMemory(salt);
                throw;
            }
        }

        /// <summary>
        /// Reads iteration number from vault header
        /// </summary>
        /// <param name="stream">Stream to read from</param>
        /// <returns>Iteration number</returns>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="stream"/> is set to null value</exception>
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

        /// <summary>
        /// Takes <see cref="Version"/>, <paramref name="salt"/> and <paramref name="iterations"/> and puts them into byte array resembling vault header
        /// </summary>
        /// <param name="salt">Salt used to derive vault key</param>
        /// <param name="iterations">Iteration count used when deriving vault key</param>
        /// <returns>Byte array </returns>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="salt"/> is set to null value</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when provided <paramref name="iterations"/> is set to negative or zero value</exception>"
        public byte[] PrepareVaultHeader(byte[] salt, int iterations)
        {
            ArgumentNullException.ThrowIfNull(salt);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);

            byte[] buffer = new byte[1 + SaltSize + sizeof(int)];
            try
            {
                buffer[0] = Version;
                Buffer.BlockCopy(salt, 0, buffer, 1, SaltSize);
                BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan().Slice(1 + SaltSize, sizeof(int)), iterations);
                return buffer;
            }
            catch(Exception)
            {
                CryptographicOperations.ZeroMemory(buffer);
                throw;
            }
        }

        
        #endregion

        #region Metadata offsets
        /// <summary>
        /// Decrypts and returns metadata offsets
        /// </summary>
        /// <param name="stream">Stream to read from</param>
        /// <returns>Array of metadata offsets</returns>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="stream"/> is set to null value</exception>
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
                if (decrypted is not null) decrypted.Dispose();
            }

        }

        private SecureBuffer.SecureLargeBuffer ReadMetadataOffsetsBytes(Stream stream)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(int), SeekOrigin.Begin);
            SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize + sizeof(ushort) + MetadataOffsetsSize); //Example: extra data (28 bytes for AES) + number of files (ushort) + max metadata offsets size
            try
            {
                stream.ReadExactly(buffer.AsSpan);
                return VaultDecryption(buffer.AsMemory);
            }
            finally
            {
                buffer.Dispose();
            }
        }

        /// <summary>
        /// Adds new offset and writes encrypted offsets to vault
        /// </summary>
        /// <param name="stream">Stream to read and write to</param>
        /// <param name="newOffset">New offset to add</param>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="stream"/> is set to null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when provided <paramref name="newOffset"/> is set to negative or zero value</exception>
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

        /// <summary>
        /// Removes offset at specified index and writes encrypted offsest to vault
        /// </summary>
        /// <param name="stream">Stream to read and write to</param>
        /// <param name="itemIndex">Index of item to remove</param>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="stream"/> is set to null</exception>
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

        private byte[] PrepareMetadataOffsets(long[] offsets)
        {
            byte[] offsetsBytes = new byte[sizeof(ushort) + (offsets.Length * sizeof(long))];
            BinaryPrimitives.WriteUInt16LittleEndian(offsetsBytes, (ushort)offsets.Length);
            Buffer.BlockCopy(offsets, 0, offsetsBytes, sizeof(ushort), offsets.Length * sizeof(long));
            return offsetsBytes;
        }

        /// <summary>
        /// Encrypts provided <paramref name="offsets"/> and replaces current metadata offsets in <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Stream to read and write to</param>
        /// <param name="offsets">Metadata offsets to save</param>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="stream"/> or <paramref name="offsets"/> are set to null</exception>
        public void SaveMetadataOffsets(Stream stream, long[] offsets)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentNullException.ThrowIfNull(offsets);

            byte[] offsetsBytes = null!;
            SecureBuffer.SecureLargeBuffer encryptedMetadataOffsets = null!;
            try
            {
                offsetsBytes = PrepareMetadataOffsets(offsets);
                encryptedMetadataOffsets = PadMetadataOffsetsAndEncrypt(offsetsBytes);
                WriteMetadataOffsets(stream, encryptedMetadataOffsets.AsSpan);
            }
            finally
            {
                if (offsetsBytes is not null) CryptographicOperations.ZeroMemory(offsetsBytes);
                if (encryptedMetadataOffsets is not null) encryptedMetadataOffsets.Dispose();
            }
        }

        /// <summary>
        /// Pads supplied <paramref name="metadataOffsets"/> to <see cref="MetadataOffsetsSize"/> and encrypts the entire collection
        /// </summary>
        /// <param name="metadataOffsets"></param>
        /// <returns></returns>
        private SecureBuffer.SecureLargeBuffer PadMetadataOffsetsAndEncrypt(byte[] metadataOffsets)
        {
            byte[] paddedMetadataOffsets = new byte[sizeof(ushort) + MetadataOffsetsSize]; //2 bytes ushort for number of currently attached offsets
            SecureBuffer.SecureLargeBuffer encryptedMetadataOffsets = null!;
            try
            {
                Buffer.BlockCopy(metadataOffsets, 0, paddedMetadataOffsets, 0, metadataOffsets.Length);
                encryptedMetadataOffsets = VaultEncryption(paddedMetadataOffsets);
                return encryptedMetadataOffsets;
            }
            catch (Exception)
            {
                if (encryptedMetadataOffsets is not null) encryptedMetadataOffsets.Dispose();
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(paddedMetadataOffsets);
            }
        }

        private void WriteMetadataOffsets(Stream stream, ReadOnlySpan<byte> encryptedMetadataOffsets)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(int), SeekOrigin.Begin); //1 byte for version + bytes for salt + 4 bytes for iterations
            stream.Write(encryptedMetadataOffsets);
        }
        #endregion

        /// <summary>
        /// Reads <paramref name="length"/> from <paramref name="stream"/> starting at <paramref name="offset"/> and decrypts it
        /// </summary>
        /// <param name="stream">Stream to read from</param>
        /// <param name="offset">Offset at where to start reading</param>
        /// <param name="length">Length to read</param>
        /// <returns>Decrypted data</returns>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="stream"/> is null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when provided <paramref name="offset"/>, <paramref name="length"/> are set to negative, or <paramref name="length"/> is set to 0 </exception>
        public SecureBuffer.SecureLargeBuffer ReadAndDecryptData(Stream stream, long offset, int length)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

            SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(length);
            try
            {
                stream.Seek(offset, SeekOrigin.Begin);
                stream.ReadExactly(buffer.AsSpan);
                return VaultDecryption(buffer.AsMemory);
            }
            finally
            {
                buffer.Dispose();
            }
        }

        /// <summary>
        /// Encrypts provided data using vault encryption algorithm
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns>Encrypted data</returns>
        /// <exception cref="ArgumentException">Thrown when provided empty data</exception>
        public SecureBuffer.SecureLargeBuffer VaultEncryption(ReadOnlyMemory<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            var provider = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider();
            return provider.EncryptionAlgorithm.EncryptBytes(data.Span, _session.GetSlicedKey(provider.KeySize));
        }

        private SecureBuffer.SecureLargeBuffer VaultDecryption(ReadOnlyMemory<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            var provider = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider();
            if (data.Length < provider.EncryptionAlgorithm.ExtraEncryptionDataSize) throw new ArgumentException("Provided data is too short", nameof(data));

            return provider.EncryptionAlgorithm.DecryptBytes(data.Span, _session.GetSlicedKey(provider.KeySize));
        }
    }


    public class VaultV0Reader : VaultReader
    {
        public VaultV0Reader(IVaultSession session) : base(session) { }

        public override byte Version => 0;
        public override byte VaultEncryptionAlgorithm => EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.ID;
    }








}
