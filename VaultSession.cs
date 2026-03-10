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
        public byte[] KEY { get; }
        public NormalizedPath VAULTPATH { get; }
        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; }
        public IVaultReader VAULT_READER { get; }
        public event Action? EncryptedFilesListUpdated;
        public void CreateSession(NormalizedPath vaultPath, IVaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations);
        public void RasiseEncryptedFileListUpdated();
        public ReadOnlyMemory<byte> GetSlicedKey(byte keySize);
        public void Dispose();
    }

    public class VaultSession : IDisposable, IVaultSession
    {

        public byte[] KEY { get; private set; }
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
            KEY = Array.Empty<byte>();
            ENCRYPTED_FILES = new();
            VAULTPATH = NormalizedPath.From(string.Empty);
            VAULT_READER = null!;
        }

        public void CreateSession(NormalizedPath vaultPath, IVaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations)
        {
            this.KEY = PasswordHelper.DeriveKey(password, salt, iterations);
            this.VAULTPATH = vaultPath;
            this.ENCRYPTED_FILES.Clear();
            this.VAULT_READER = vaultReader;
        }

        public void RasiseEncryptedFileListUpdated()
        {
            this.EncryptedFilesListUpdated?.Invoke();
        }

        public ReadOnlyMemory<byte> GetSlicedKey(byte keySize)
        {
            if (keySize > this.KEY.Length) throw new ArgumentOutOfRangeException("Requested bigger slice than the length of entire key");
            return this.KEY.AsMemory(0, keySize);
        }

        /// <summary>
        /// Clears the sensitive vault session data from memory
        /// </summary>
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(KEY);
            //Attempting to hide size of KEY by making it an empty array instead of zero-ed one
            KEY = Array.Empty<byte>();
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
        

        public static VaultRegistry Initialize(IVaultSession session, IEncryptionOptionsService encryptionOptionsService)
        {
            return Current = new VaultRegistry(session, encryptionOptionsService);
        }
        private VaultRegistry(IVaultSession session, IEncryptionOptionsService encryptionOptionsService)
        {
            registry = new()
            {
                {0, new Lazy<IVaultReader>(() => new VaultV0Reader(session, encryptionOptionsService)) }
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
        /// Populates <see cref="IVaultSession.ENCRYPTED_FILES"/> list with the information from the <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Vault file to read from</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is set to null</exception>
        public void PopulateEncryptedFilesList(Stream stream);

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
        public byte[] ReadAndDecryptData(Stream stream, long offset, int length);

        /// <summary>
        /// Encrypts <paramref name="data"/> using <see cref="VaultEncryptionAlgorithm"/>
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns>Encrypted information</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="data"/> is empty</exception>
        public byte[] VaultEncryption(ReadOnlyMemory<byte> data);

    }

    //For new versions append the additional data at the end
    //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number +  MetadataOffsetsSize (4KB (4096 bytes))]...
    public abstract class VaultReader : IVaultReader
    {
        public abstract byte Version { get; }
        public abstract byte VaultEncryptionAlgorithm { get; }
        public virtual ushort SaltSize => 32;
        public virtual ushort EncryptionOptionsSize => 1024;
        public virtual ushort MetadataOffsetsSize => 4096;
        public virtual ushort HeaderSize => (ushort)(1 + SaltSize + sizeof(int) + EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize + sizeof(ushort) + MetadataOffsetsSize);

        private readonly IVaultSession _session;
        private readonly IEncryptionOptionsService _encryptionOptionsService;

        protected VaultReader(IVaultSession session, IEncryptionOptionsService encryptionOptionsService)
        {
            this._session = session;
            this._encryptionOptionsService = encryptionOptionsService;
        }

        #region Vault header
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

        public virtual void PopulateEncryptedFilesList(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            long[] offsets = null!;
            try
            {
                offsets = ReadMetadataOffsets(stream);
                foreach (long offset in offsets)
                {
                    EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = null!;
                    try
                    {
                        fileEncryptionOptions = _encryptionOptionsService.GetDecryptedFileEncryptionOptions(stream, offset);
                        try
                        {
                            _session.ENCRYPTED_FILES.Add(offset, new EncryptedFileInfo(Encoding.UTF8.GetString(fileEncryptionOptions.FileName), fileEncryptionOptions.FileSize, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[fileEncryptionOptions.EncryptionAlgorithm]));
                        }
                        catch (ArgumentException)
                        {
                            //Dictionary entry with the same key already exists, replace it
                            _session.ENCRYPTED_FILES[offset] = new EncryptedFileInfo(Encoding.UTF8.GetString(fileEncryptionOptions.FileName), fileEncryptionOptions.FileSize, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[fileEncryptionOptions.EncryptionAlgorithm]);
                        }
                        
                    }
                    catch(Exception)
                    {
                        _session.ENCRYPTED_FILES.Add(offset, new EncryptedFileInfo(null, 0, null));
                    }
                    finally
                    {
                        if (fileEncryptionOptions is not null) fileEncryptionOptions.Dispose();
                    }
                }
            }
            finally
            {
                if (offsets is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(offsets.AsSpan()));
            }
        }
        #endregion

        #region Metadata offsets
        private long[] ReadMetadataOffsets(Stream stream)
        {
            byte[] decrypted = null!;
            long[] offsets = null!;
            try
            {
                decrypted = ReadMetadataOffsetsBytes(stream);
                ushort fileCount = BinaryPrimitives.ReadUInt16LittleEndian(decrypted);

                offsets = new long[fileCount];
                for (int i = 0; i < fileCount; i++)
                {
                    int readOffset = sizeof(ushort) + (i * sizeof(long));
                    offsets[i] = BinaryPrimitives.ReadInt64LittleEndian(decrypted.AsSpan(readOffset, sizeof(long)));
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
                if (decrypted is not null) CryptographicOperations.ZeroMemory(decrypted);
            }

        }

        private byte[] ReadMetadataOffsetsBytes(Stream stream)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(int), SeekOrigin.Begin);
            byte[] buffer = new byte[EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize + sizeof(ushort) + MetadataOffsetsSize]; //Example: extra data (28 bytes for AES) + number of files (ushort) + max metadata offsets size
            try
            {
                stream.ReadExactly(buffer);
                return VaultDecryption(buffer);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }

        /// <summary>
        /// Adds new offset and writes encrypted offsets to vault
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="newOffset"></param>
        /// <exception cref="Exception"></exception>
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
        /// <param name="stream"></param>
        /// <param name="itemIndex"></param>
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

        public void SaveMetadataOffsets(Stream stream, long[] offsets)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentNullException.ThrowIfNull(offsets);

            byte[] offsetsBytes = null!;
            byte[] encryptedMetadataOffsets = null!;
            try
            {
                offsetsBytes = PrepareMetadataOffsets(offsets);
                encryptedMetadataOffsets = PadMetadataOffsetsAndEncrypt(offsetsBytes);
                WriteMetadataOffsets(stream, encryptedMetadataOffsets);
            }
            finally
            {
                if (offsetsBytes is not null) CryptographicOperations.ZeroMemory(offsetsBytes);
                if (encryptedMetadataOffsets is not null) CryptographicOperations.ZeroMemory(encryptedMetadataOffsets);
            }
        }

        /// <summary>
        /// Pads supplied <paramref name="metadataOffsets"/> to <see cref="MetadataOffsetsSize"/> and encrypts the entire collection
        /// </summary>
        /// <param name="metadataOffsets"></param>
        /// <returns></returns>
        private byte[] PadMetadataOffsetsAndEncrypt(byte[] metadataOffsets)
        {
            byte[] paddedMetadataOffsets = new byte[sizeof(ushort) + MetadataOffsetsSize]; //2 bytes ushort for number of currently attached offsets
            byte[] encryptedMetadataOffsets = null!;
            try
            {
                Buffer.BlockCopy(metadataOffsets, 0, paddedMetadataOffsets, 0, metadataOffsets.Length);
                encryptedMetadataOffsets = VaultEncryption(paddedMetadataOffsets);
                return encryptedMetadataOffsets;
            }
            catch (Exception)
            {
                if (encryptedMetadataOffsets is not null) CryptographicOperations.ZeroMemory(encryptedMetadataOffsets);
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(paddedMetadataOffsets);
            }
        }

        private void WriteMetadataOffsets(Stream stream, byte[] encryptedMetadataOffsets)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(int), SeekOrigin.Begin); //1 byte for version + bytes for salt + 4 bytes for iterations
            stream.Write(encryptedMetadataOffsets);
        }
        #endregion


        public byte[] ReadAndDecryptData(Stream stream, long offset, int length)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(offset);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

            byte[] buffer = new byte[length];
            try
            {
                stream.Seek(offset, SeekOrigin.Begin);
                stream.ReadExactly(buffer, 0, length);
                return VaultDecryption(buffer);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }

        public byte[] VaultEncryption(ReadOnlyMemory<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            var provider = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider();
            return provider.EncryptionAlgorithm.EncryptBytes(data.Span, _session.GetSlicedKey(provider.KeySize).Span);
        }

        private byte[] VaultDecryption(ReadOnlyMemory<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            var provider = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].Provider();
            return provider.EncryptionAlgorithm.DecryptBytes(data.Span, _session.GetSlicedKey(provider.KeySize).Span);
        }
    }


    public class VaultV0Reader : VaultReader
    {
        public VaultV0Reader(IVaultSession session, IEncryptionOptionsService encryptionOptionsService) : base(session, encryptionOptionsService) { }

        public override byte Version => 0;
        public override byte VaultEncryptionAlgorithm => EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.ID;
    }








}
