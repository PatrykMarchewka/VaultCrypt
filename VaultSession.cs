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
        public VaultReader VAULT_READER { get; }
        public event Action? EncryptedFilesListUpdated;
        public void CreateSession(NormalizedPath vaultPath, VaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations);
        public void RasiseEncryptedFileListUpdated();
    }

    public class VaultSession : IDisposable, IVaultSession
    {

        public byte[] KEY { get; private set; }
        public NormalizedPath VAULTPATH { get; private set; }
        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; private set; }
        public VaultReader VAULT_READER { get; private set; }

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

        public void CreateSession(NormalizedPath vaultPath, VaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations)
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

    public class VaultRegistry
    {
        private readonly IVaultSession _session;
        private readonly IEncryptionOptionsService _encryptionOptionsService;
        private static Dictionary<byte, Lazy<VaultReader>> registry = null!;
        public VaultRegistry(IVaultSession session, IEncryptionOptionsService encryptionOptionsService)
        {
            this._session = session;
            this._encryptionOptionsService = encryptionOptionsService;

            registry = new()
            {
                {0, new Lazy<VaultReader>(() => new VaultV0Reader(session, encryptionOptionsService)) }
            };
        }

        public static VaultReader GetVaultReader(byte version)
        {
            return registry.TryGetValue(version, out var reader) ? reader.Value : throw new VaultException(VaultException.ErrorContext.VaultSession, VaultException.ErrorReason.NoReader);
        }
    }

    //For new versions append the additional data at the end
    //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096 bytes)]...
    public abstract class VaultReader
    {
        public abstract byte Version { get; } //Numeric version of the vault
        public abstract byte VaultEncryptionAlgorithm { get; } //Default encryption algorithm ID to encrypt vault metadata with
        public virtual short SaltSize => 32; //Size in bytes of the salt
        public virtual short EncryptionOptionsSize => 1024; //Size of already encrypted EncryptionOptions
        public virtual short MetadataOffsetsSize => 4096; //Size of metadata offsets collection before encryption
        public virtual short HeaderSize => (short)(1 + SaltSize + sizeof(int) + EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].provider().EncryptionAlgorithm.ExtraEncryptionDataSize + sizeof(ushort) + MetadataOffsetsSize); //Full size of vault header

        private readonly IVaultSession _session;
        private readonly IEncryptionOptionsService _encryptionOptionsService;

        public VaultReader(IVaultSession session, IEncryptionOptionsService encryptionOptionsService)
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

            byte[] buffer = new byte[1 + SaltSize + sizeof(uint)];
            try
            {
                buffer[0] = Version;
                Buffer.BlockCopy(salt, 0, buffer, 1, SaltSize);
                BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan().Slice(1 + SaltSize, sizeof(uint)), iterations);
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
                byte[] decrypted = null!;
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
                        if (decrypted is not null) CryptographicOperations.ZeroMemory(decrypted);
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

        internal virtual byte[] ReadMetadataOffsetsBytes(Stream stream)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(uint), SeekOrigin.Begin);
            byte[] buffer = new byte[EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].provider().EncryptionAlgorithm.ExtraEncryptionDataSize + sizeof(ushort) + MetadataOffsetsSize]; //Example: extra data (28 bytes for AES) + number of files (ushort) + max metadata offsets size
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
        internal virtual void AddAndSaveMetadataOffsets(Stream stream, long newOffset)
        {
            long[] oldOffsets = null!;
            long[] newOffsets = null!;
            try
            {
                oldOffsets = ReadMetadataOffsets(stream);
                if (oldOffsets.Length + 1 > (sizeof(ushort) + MetadataOffsetsSize))
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
        internal void RemoveAndSaveMetadataOffsets(Stream stream, ushort itemIndex)
        {
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

        internal virtual byte[] PrepareMetadataOffsets(long[] offsets)
        {
            byte[] offsetsBytes = new byte[sizeof(ushort) + (offsets.Length * sizeof(long))];
            Buffer.BlockCopy(offsets, 0, offsetsBytes, sizeof(ushort), offsets.Length * sizeof(long));
            BinaryPrimitives.WriteUInt16LittleEndian(offsetsBytes.AsSpan(0, sizeof(ushort)), (ushort)(offsets.Length));
            return offsetsBytes;
        }

        internal void SaveMetadataOffsets(Stream stream, long[] offsets)
        {
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

        internal virtual void WriteMetadataOffsets(Stream stream, byte[] encryptedMetadataOffsets)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(uint), SeekOrigin.Begin); //1 byte for version + bytes for salt + 4 bytes for iterations
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

        public virtual byte[] VaultEncryption(ReadOnlyMemory<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            byte[] slicedKey = new byte[EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].provider().KeySize];
            try
            {
                Buffer.BlockCopy(_session.KEY, 0, slicedKey, 0, slicedKey.Length);
                return EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].provider().EncryptionAlgorithm.EncryptBytes(data.Span, slicedKey);
            }
            catch(Exception)
            {
                CryptographicOperations.ZeroMemory(slicedKey);
                throw;
            }
            
        }

        public virtual byte[] VaultDecryption(ReadOnlyMemory<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            byte[] slicedKey = new byte[EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].provider().KeySize];
            try
            {
                Buffer.BlockCopy(_session.KEY, 0, slicedKey, 0, slicedKey.Length);
                return EncryptionAlgorithm.GetEncryptionAlgorithmInfo[VaultEncryptionAlgorithm].provider().EncryptionAlgorithm.DecryptBytes(data.Span, slicedKey);
            }
            catch(Exception)
            {
                CryptographicOperations.ZeroMemory(slicedKey);
                throw;
            }
            
        }
    }


    public class VaultV0Reader : VaultReader
    {
        public VaultV0Reader(IVaultSession session, IEncryptionOptionsService encryptionOptionsService) : base(session, encryptionOptionsService) { }

        public override byte Version => 0;
        public override byte VaultEncryptionAlgorithm => EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.ID;
    }








}
