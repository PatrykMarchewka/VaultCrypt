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
        internal virtual void ReadVaultSession(Stream stream)
        {
            long[] offsets = ReadMetadataOffsets(stream);

            Span<byte> buffer = stackalloc byte[1024];
            foreach (var item in offsets)
            {
                stream.Seek(item, SeekOrigin.Begin);
                stream.ReadExactly(buffer);
                byte[] decrypted = VaultDecryption(buffer);
                CryptographicOperations.ZeroMemory(buffer);
                byte version = decrypted[0];
                EncryptionOptionsReader reader = EncryptionOptionsRegistry.GetReader(version);
                EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = reader.DeserializeEncryptionOptions(decrypted);
                CryptographicOperations.ZeroMemory(decrypted);
                VaultSession.ENCRYPTED_FILES.Add(item, Encoding.UTF8.GetString(fileEncryptionOptions.fileName));
                EncryptionOptions.WipeFileEncryptionOptions(ref fileEncryptionOptions);
            }
        }

        internal virtual void ReadVaultHeader(Stream stream)
        {
            //v0 = [version (1byte)] + [salt (32 bytes)][iterations (4 bytes)]...
            Span<byte> buffer = stackalloc byte[32 + sizeof(uint)]; //Default salt size + 4 for uint ITERATIONS
            stream.ReadExactly(buffer);
            VaultSession.SALT = buffer[..32].ToArray();
            VaultSession.ITERATIONS = BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(32, sizeof(uint)));
            CryptographicOperations.ZeroMemory(buffer);
        }

        internal virtual long[] ReadMetadataOffsets(Stream stream)
        {
            byte[] decrypted = ReadMetadataOffsetsBytes(stream);
            ushort fileCount = BinaryPrimitives.ReadUInt16LittleEndian(decrypted);

            long[] offsets = new long[fileCount];
            for (int i = 0; i < fileCount; i++)
            {
                int readOffset = 2 + (i * sizeof(long));
                offsets[i] = BinaryPrimitives.ReadInt64LittleEndian(decrypted.AsSpan(readOffset, sizeof(long)));
            }
            CryptographicOperations.ZeroMemory(decrypted);
            return offsets;
        }

        internal virtual byte[] ReadMetadataOffsetsBytes(Stream stream)
        {
            //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096 bytes)]...
            stream.Seek(sizeof(byte) + 32 + sizeof(uint), SeekOrigin.Begin);
            Span<byte> buffer = stackalloc byte[28 + sizeof(ushort) + 4096]; //28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096) for maximum of 512 files per vault
            stream.ReadExactly(buffer);
            return VaultDecryption(buffer);
        }

        internal virtual void WriteMetadataOffsets(Stream stream, long newOffset)
        {
            long[] oldOffsets = ReadMetadataOffsets(stream);
            long[] newOffsets = new long[oldOffsets.Length + 1];
            Array.Copy(oldOffsets, newOffsets, oldOffsets.Length);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(oldOffsets.AsSpan()));
            newOffsets[oldOffsets.Length + 1] = newOffset;
            byte[] data = new byte[sizeof(ushort) + newOffsets.Length * sizeof(long)];
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0, sizeof(ushort)), (ushort)(newOffsets.Length));
            for (int i = 0; i < newOffsets.Length; i++)
            {
                int writeOffset = sizeof(ushort) + i * sizeof(long);
                BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(writeOffset, sizeof(long)), newOffsets[i]);
            }
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(newOffsets.AsSpan()));
            byte[] encryptedMetadataOffsets = VaultEncryption(data);
            CryptographicOperations.ZeroMemory(data);
            if (encryptedMetadataOffsets.Length > (28 + sizeof(ushort) + 4096))
            {
                throw new Exception("Too many files in the vault");
            }

            byte[] paddedMetadataOffsets = new byte[28 + sizeof(ushort) + 4096]; //28 bytes for AES encryption + 2 bytes ushort number + 4KB (4096) for maximum of 512 files per vault
            Buffer.BlockCopy(encryptedMetadataOffsets, 0, paddedMetadataOffsets, 0, encryptedMetadataOffsets.Length);

            //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096 bytes)]...
            stream.Seek(sizeof(byte) + 32 + sizeof(uint), SeekOrigin.Begin); //1 byte for version + 32 bytes for salt + 4 bytes for iterations
            stream.Write(paddedMetadataOffsets);
        }

        internal virtual byte[] VaultEncryption(byte[] data)
        {
            byte[] slicedKey = new byte[32];
            Buffer.BlockCopy(VaultSession.KEY, 0, slicedKey, 0, slicedKey.Length);

            return Encryption.AesGcmEncryption.EncryptBytes(data, slicedKey);
        }

        internal virtual byte[] VaultDecryption(Span<byte> data)
        {
            byte[] slicedKey = new byte[32];
            Buffer.BlockCopy(VaultSession.KEY, 0, slicedKey, 0, slicedKey.Length);

            return Decryption.AesGcmDecryption.DecryptBytes(data, slicedKey);
        }
    }






    internal class VaultV0Reader : VaultReader
    {
        internal override byte Version => 0;
    }








}
