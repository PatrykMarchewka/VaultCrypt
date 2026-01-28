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

namespace VaultCrypt
{
    internal class VaultSession : IDisposable
    {
        
        internal byte[] KEY { get; private set; }
        internal NormalizedPath VAULTPATH { get; private set; }
        internal Dictionary<long, string> ENCRYPTED_FILES { get; private set; }
        internal VaultReader VAULT_READER { get; private set; }

        internal static VaultSession CurrentSession;
        private const byte NewestVaultVersion = 0;
        internal static event Action? EncryptedFilesListUpdated;

        internal VaultSession(NormalizedPath vaultPath, VaultReader vaultReader, byte[] password, byte[] salt, int iterations)
        {
            this.KEY = PasswordHelper.DeriveKey(password, salt, iterations);
            this.VAULTPATH = vaultPath;
            this.ENCRYPTED_FILES = new();
            this.VAULT_READER = vaultReader;
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
        internal static void CreateVault(NormalizedPath folderPath, string vaultName, byte[] password, int iterations)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(folderPath);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(vaultName);
            ArgumentNullException.ThrowIfNull(password);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);

            NormalizedPath vaultPath = NormalizedPath.From($"{folderPath}\\{vaultName}.vlt")!;
            VaultReader reader = VaultRegistry.GetVaultReader(NewestVaultVersion);
            byte[] salt = null!;
            byte[] buffer = null!;
            byte[] encryptedMetadata = null!;
            byte[] data = null!;
            try
            {
                salt = PasswordHelper.GenerateRandomSalt(reader.SaltSize);
                buffer = reader.PrepareVaultHeader(salt, iterations);
                encryptedMetadata = reader.VaultEncryption(new byte[sizeof(ushort) + reader.MetadataOffsetsSize]);
                data = new byte[buffer.Length + encryptedMetadata.Length];
                Buffer.BlockCopy(buffer, 0, data, 0, buffer.Length);
                Buffer.BlockCopy(encryptedMetadata, 0, data, buffer.Length, encryptedMetadata.Length);
                File.WriteAllBytes(vaultPath!, data);
                VaultSession.CurrentSession = new VaultSession(vaultPath, reader, password, salt, iterations);
            }
            finally
            {
                if (salt is not null) CryptographicOperations.ZeroMemory(salt);
                if (buffer is not null) CryptographicOperations.ZeroMemory(buffer);
                if (encryptedMetadata is not null) CryptographicOperations.ZeroMemory(encryptedMetadata);
                if (data is not null) CryptographicOperations.ZeroMemory(data);
            }

            
        }
        internal static void RefreshEncryptedFilesList(Stream vaultFS)
        {
            ArgumentNullException.ThrowIfNull(vaultFS);

            try
            {
                VaultSession.CurrentSession.ENCRYPTED_FILES.Clear();
                VaultSession.CurrentSession.VAULT_READER.PopulateEncryptedFilesList(vaultFS);
            }
            catch(Exception ex)
            {
                throw new VaultException("Failed to refresh file list", ex);
            }
            finally
            {
                EncryptedFilesListUpdated?.Invoke();
            }
        }

        /// <summary>
        /// Creates new vault session
        /// </summary>
        /// <param name="password">Password to unlock the vault with</param>
        /// <param name="path">Path to the vault with extension</param>
        public static void CreateSession(byte[] password, NormalizedPath path)
        {
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(path);

            try
            {
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
                    CurrentSession = new VaultSession(path, reader, password, salt, iterations);
                }
                finally
                {
                    if(salt is not null) CryptographicOperations.ZeroMemory(salt);
                }
                RefreshEncryptedFilesList(fs);

            }
            catch(EndOfStreamException ex)
            {
                throw VaultException.EndOfFileException(ex);
            }
            catch(Exception ex)
            {
                throw new VaultException("Failed to create session", ex);
            }

            

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
            VAULTPATH = NormalizedPath.From(string.Empty)!;
            VAULT_READER = null!;
        }

    }

    internal static class VaultRegistry
    {
        private static readonly Dictionary<byte, Lazy<VaultReader>> registry = new()
        {
            {0, new Lazy<VaultReader>(() => new VaultV0Reader()) }
        };

        internal static VaultReader GetVaultReader(byte version)
        {
            if (!registry.TryGetValue(version, out Lazy<VaultReader> reader))
            {
                throw new VaultException($"Unknown vault version ({version})");
            }
            return reader.Value;
        }
    }







    //For new versions append the additional data at the end
    //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096 bytes)]...
    internal abstract class VaultReader
    {
        internal abstract byte Version { get; } //Numeric version of the vault
        internal abstract EncryptionOptions.EncryptionProtocol EncryptionProtocol { get; } //Default encryption protocol to encrypt vault metadata with
        internal virtual short SaltSize => 32; //Size in bytes of the salt
        internal virtual short EncryptionOptionsSize => 1024; //Size of already encrypted EncryptionOptions
        internal virtual short MetadataOffsetsSize => 4096; //Size of metadata offsets collection before encryption
        internal virtual short HeaderSize => (short)(1 + SaltSize + sizeof(int) + EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].encryptionDataSize + sizeof(ushort) + MetadataOffsetsSize); //Full size of vault header

        #region Vault header
        internal byte[] ReadSalt(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            byte[] salt = new byte[SaltSize];
            try
            {
                stream.Seek(1, SeekOrigin.Begin);
                stream.ReadExactly(salt);
                return salt;
            }
            catch (Exception ex)
            {
                CryptographicOperations.ZeroMemory(salt);
                throw new VaultException("Failed to get salt", ex);
            }
        }

        internal int ReadIterationsNumber(Stream stream)
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

        internal byte[] PrepareVaultHeader(byte[] salt, int iterations)
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
            catch(Exception ex)
            {
                CryptographicOperations.ZeroMemory(buffer);
                throw new VaultException("Failed to create vault header", ex);
            }
        }

        internal virtual void PopulateEncryptedFilesList(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            long[] offsets = null!;
            try
            {
                offsets = ReadMetadataOffsets(stream);
                byte[] decrypted = null!;
                foreach (long offset in offsets)
                {
                    EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = new();
                    try
                    {
                        decrypted = ReadAndDecryptData(stream, offset, EncryptionOptionsSize);
                        fileEncryptionOptions = EncryptionOptionsRegistry.GetReader(decrypted[0]).DeserializeEncryptionOptions(decrypted);
                        VaultSession.CurrentSession.ENCRYPTED_FILES.Add(offset, Encoding.UTF8.GetString(fileEncryptionOptions.fileName));
                    }
                    catch
                    {
                        VaultSession.CurrentSession.ENCRYPTED_FILES.Add(offset, "Unknown file (Corrupted data!)");
                        continue;
                    }
                    finally
                    {
                        if (decrypted is not null) CryptographicOperations.ZeroMemory(decrypted);
                        EncryptionOptions.WipeFileEncryptionOptions(ref fileEncryptionOptions);
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
            catch (Exception ex)
            {
                if (offsets is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(offsets.AsSpan()));
                throw new VaultException("Failed to read metadata offsets", ex);
            }
            finally
            {
                if (decrypted is not null) CryptographicOperations.ZeroMemory(decrypted);
            }

        }

        internal virtual byte[] ReadMetadataOffsetsBytes(Stream stream)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(uint), SeekOrigin.Begin);
            byte[] buffer = new byte[EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].encryptionDataSize + sizeof(ushort) + MetadataOffsetsSize]; //28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096) for maximum of 512 files per vault
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
                    throw new VaultException("Cannot add any more files to this vault");
                }
                newOffsets = new long[oldOffsets.Length + 1];
                oldOffsets.AsSpan().CopyTo(newOffsets);
                newOffsets[oldOffsets.Length] = newOffset;
                SaveMetadataOffsets(stream, newOffsets);
            }
            catch (Exception ex)
            {
                throw new VaultException("Failed to add new metadata offset", ex);
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
            catch (Exception ex)
            {
                throw new VaultException($"Failed to remove metadata offset for item {itemIndex + 1}", ex);
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
            catch (Exception ex)
            {
                if (encryptedMetadataOffsets is not null) CryptographicOperations.ZeroMemory(encryptedMetadataOffsets);
                throw new VaultException("Failed to pad and encrypt metadata offsets", ex);
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


        internal byte[] ReadAndDecryptData(Stream stream, long offset, int length)
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

        

        internal virtual byte[] VaultEncryption(ReadOnlyMemory<byte> data)
        {
            if (data.Length == 0) throw new VaultException("Failed to encrypt vault metadata, provided data was empty");

            byte[] slicedKey = new byte[EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].keySize];
            try
            {
                Buffer.BlockCopy(VaultSession.CurrentSession.KEY, 0, slicedKey, 0, slicedKey.Length);
                return EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].encryptMethod.Invoke(data, slicedKey);
            }
            catch(Exception ex)
            {
                CryptographicOperations.ZeroMemory(slicedKey);
                throw new VaultException("Failed to encrypt vault metadata", ex);
            }
            
        }

        internal virtual byte[] VaultDecryption(ReadOnlyMemory<byte> data)
        {
            if (data.Length == 0) throw new VaultException("Failed to decrypt vault metadata, provided data was empty");

            byte[] slicedKey = new byte[EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].keySize];
            try
            {
                Buffer.BlockCopy(VaultSession.CurrentSession.KEY, 0, slicedKey, 0, slicedKey.Length);
                return EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].decryptMethod.Invoke(data, slicedKey);
            }
            catch(Exception ex)
            {
                CryptographicOperations.ZeroMemory(slicedKey);
                throw new VaultException("Failed to decrypt vault metadata", ex);
            }
            
        }
    }


    internal class VaultV0Reader : VaultReader
    {
        internal override byte Version => 0;
        internal override EncryptionOptions.EncryptionProtocol EncryptionProtocol => EncryptionOptions.EncryptionProtocol.AES256GCM;
    }








}
