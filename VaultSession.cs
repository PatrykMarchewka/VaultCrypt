using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal static class VaultSession
    {
        internal static byte VERSION;
        internal static byte[] KEY;
        internal static NormalizedPath VAULTPATH;
        internal static int ITERATIONS;
        internal static byte[] SALT;
        internal static Dictionary<long, string> ENCRYPTED_FILES = new();

        //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)][metadata offsets (28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096 bytes)][File #1 encryption options][File #1]...
        public static void CreateSession(byte[] password, NormalizedPath path)
        {
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(path);

            VAULTPATH = path;
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                Span<byte> buffer = stackalloc byte[1];
                fs.ReadExactly(buffer);
                VERSION = buffer[0];

                VaultReader reader = VaultRegistry.GetVaultReader(VERSION);
                reader.ReadVaultHeader(fs);
                KEY = PasswordHelper.DeriveKey(password);
                reader.ReadVaultSession(fs);
            }
        }


        public static void Dispose()
        {
            CryptographicOperations.ZeroMemory(KEY);
            CryptographicOperations.ZeroMemory(SALT);
            ENCRYPTED_FILES.Clear();
            VAULTPATH = NormalizedPath.From(String.Empty);
            ITERATIONS = 0;
            VERSION = 0;
        }

    }

    internal static class VaultHelper
    {
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

            NormalizedPath vaultPath = NormalizedPath.From(folderPath + "\\" + vaultName + ".vlt");
            SetVaultSessionInfo(vaultPath, iterations, password);
            VaultReader reader = VaultRegistry.GetVaultReader(VaultSession.VERSION);
            byte[] buffer = PrepareVaultHeader(reader.SaltSize, iterations);
            byte[] encryptedMetadata = reader.VaultEncryption(new byte[sizeof(ushort) + reader.MetadataOffsetsSize]);
            byte[] data = new byte[buffer.Length + encryptedMetadata.Length];
            Buffer.BlockCopy(buffer, 0, data, 0, buffer.Length);
            Buffer.BlockCopy(encryptedMetadata, 0, data, buffer.Length, encryptedMetadata.Length);
            File.WriteAllBytes(VaultSession.VAULTPATH, data);
        }

        /// <summary>
        /// Prepares vault header
        /// </summary>
        /// <param name="saltSize">Size of the salt</param>
        /// <param name="iterations">Number of PBKDF2 iterations</param>
        /// <returns>Byte array with vault header</returns>
        private static byte[] PrepareVaultHeader(short saltSize, int iterations)
        {
            byte[] buffer = new byte[1 + saltSize + sizeof(uint)]; //1 byte for version + 32 byte salt + 4 bytes for iterations number
            buffer[0] = VaultSession.VERSION;
            byte[] salt = VaultSession.SALT;
            Buffer.BlockCopy(salt, 0, buffer, 1, saltSize);
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan().Slice(1 + saltSize, sizeof(uint)), iterations);
            return buffer;
        }

        private static void SetVaultSessionInfo(NormalizedPath vaultPath, int iterations, byte[] password)
        {
            VaultSession.VERSION = 0;
            VaultSession.VAULTPATH = vaultPath;
            VaultSession.SALT = PasswordHelper.GenerateRandomSalt();
            VaultSession.ITERATIONS = iterations;
            VaultSession.KEY = PasswordHelper.DeriveKey(password);
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
                throw new Exception("Unknown vault version");
            }
            return reader.Value;
        }
    }


    internal abstract class VaultReader
    {
        internal abstract byte Version { get; }
        internal abstract EncryptionOptions.EncryptionProtocol EncryptionProtocol { get; }
        internal virtual short ExtraEncryptionDataSize => EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].encryptionDataSize; //Size in bytes of extra data added by encrypting
        internal virtual short SaltSize => 32; //Size in bytes of the salt
        internal virtual short KeySize => EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].keySize; //Size in bytes of the key used to encrypt/decrypt vault data
        internal virtual short EncryptionOptionsSize => 1024; //Size of already encrypted EncryptionOptions
        internal virtual short MetadataOffsetsSize => 4096; //Size of metadata offsets before encryption



        internal virtual void ReadVaultSession(Stream stream)
        {
            long[] offsets = ReadMetadataOffsets(stream);

            Span<byte> buffer = stackalloc byte[EncryptionOptionsSize];
            foreach (long offset in offsets)
            {
                stream.Seek(offset, SeekOrigin.Begin);
                stream.ReadExactly(buffer);
                byte[] decrypted = VaultDecryption(buffer);
                CryptographicOperations.ZeroMemory(buffer);
                byte version = decrypted[0];
                EncryptionOptionsReader reader = EncryptionOptionsRegistry.GetReader(version);
                EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = reader.DeserializeEncryptionOptions(decrypted);
                CryptographicOperations.ZeroMemory(decrypted);
                VaultSession.ENCRYPTED_FILES.Add(offset, Encoding.UTF8.GetString(fileEncryptionOptions.fileName));
                EncryptionOptions.WipeFileEncryptionOptions(ref fileEncryptionOptions);
            }
        }

        internal virtual void ReadVaultHeader(Stream stream)
        {
            //v0 = [version (1byte)] + [salt (32 bytes)][iterations (4 bytes)]...
            Span<byte> buffer = stackalloc byte[SaltSize + sizeof(uint)]; //Default salt size + 4 for uint ITERATIONS
            stream.ReadExactly(buffer);
            VaultSession.SALT = buffer[..SaltSize].ToArray();
            VaultSession.ITERATIONS = BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(SaltSize, sizeof(uint)));
            CryptographicOperations.ZeroMemory(buffer);
        }

        internal virtual long[] ReadMetadataOffsets(Stream stream)
        {
            byte[] decrypted = ReadMetadataOffsetsBytes(stream);
            ushort fileCount = BinaryPrimitives.ReadUInt16LittleEndian(decrypted);

            long[] offsets = new long[fileCount];
            for (int i = 0; i < fileCount; i++)
            {
                int readOffset = sizeof(ushort) + (i * sizeof(long));
                offsets[i] = BinaryPrimitives.ReadInt64LittleEndian(decrypted.AsSpan(readOffset, sizeof(long)));
            }
            CryptographicOperations.ZeroMemory(decrypted);
            return offsets;
        }

        internal virtual byte[] ReadMetadataOffsetsBytes(Stream stream)
        {
            //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096 bytes)]...
            stream.Seek(sizeof(byte) + SaltSize + sizeof(uint), SeekOrigin.Begin);
            Span<byte> buffer = stackalloc byte[ExtraEncryptionDataSize + sizeof(ushort) + MetadataOffsetsSize]; //28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096) for maximum of 512 files per vault
            stream.ReadExactly(buffer);
            return VaultDecryption(buffer);
        }

        /// <summary>
        /// Adds new offset and writes encrypted offsets to vault
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="newOffset"></param>
        /// <exception cref="Exception"></exception>
        internal virtual void WriteMetadataOffsets(Stream stream, long newOffset)
        {
            long[] oldOffsets = ReadMetadataOffsets(stream);
            long[] newOffsets = new long[oldOffsets.Length + 1];
            Buffer.BlockCopy(oldOffsets, 0, newOffsets, 0, oldOffsets.Length * sizeof(long));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(oldOffsets.AsSpan()));
            newOffsets[oldOffsets.Length] = newOffset;
            byte[] data = new byte[sizeof(ushort) + (newOffsets.Length * sizeof(long))];
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0, sizeof(ushort)), (ushort)(newOffsets.Length));
            for (int i = 0; i < newOffsets.Length; i++)
            {
                int writeOffset = sizeof(ushort) + (i * sizeof(long));
                BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(writeOffset, sizeof(long)), newOffsets[i]);
            }
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(newOffsets.AsSpan()));
            if (data.Length > (sizeof(ushort) + MetadataOffsetsSize))
            {
                throw new Exception("Too many files in the vault");
            }
            byte[] paddedMetadataOffsets = new byte[sizeof(ushort) + MetadataOffsetsSize]; //2 bytes ushort number + 4KB (4096) for maximum of 512 files per vault
            Buffer.BlockCopy(data, 0, paddedMetadataOffsets, 0, data.Length);
            CryptographicOperations.ZeroMemory(data);
            byte[] encryptedMetadataOffsets = VaultEncryption(paddedMetadataOffsets);
            CryptographicOperations.ZeroMemory(paddedMetadataOffsets);

            //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096 bytes)]...
            stream.Seek(sizeof(byte) + SaltSize + sizeof(uint), SeekOrigin.Begin); //1 byte for version + 32 bytes for salt + 4 bytes for iterations
            stream.Write(encryptedMetadataOffsets);
        }

        internal virtual byte[] VaultEncryption(byte[] data)
        {
            byte[] slicedKey = new byte[KeySize];
            Buffer.BlockCopy(VaultSession.KEY, 0, slicedKey, 0, slicedKey.Length);

            return Encryption.AesGcmEncryption.EncryptBytes(data, slicedKey);
        }

        internal virtual byte[] VaultDecryption(Span<byte> data)
        {
            byte[] slicedKey = new byte[KeySize];
            Buffer.BlockCopy(VaultSession.KEY, 0, slicedKey, 0, slicedKey.Length);

            return Decryption.AesGcmDecryption.DecryptBytes(data, slicedKey);
        }
    }






    internal class VaultV0Reader : VaultReader
    {
        internal override byte Version => 0;
        internal override EncryptionOptions.EncryptionProtocol EncryptionProtocol => EncryptionOptions.EncryptionProtocol.AES256GCM;
    }








}
