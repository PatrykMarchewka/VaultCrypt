using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class VaultSession : IDisposable
    {
        internal static byte VERSION;
        internal static byte[] KEY;
        internal static NormalizedPath VAULTPATH;
        internal static int ITERATIONS;
        internal static byte[] SALT;
        internal static Dictionary<long, EncryptionOptions.FileEncryptionOptions> ENCRYPTED_FILES;

        internal VaultSession(string password, NormalizedPath path)
        {
            VAULTPATH = path;
            KEY = PasswordHelper.DeriveKey(password);
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                Span<byte> buffer = stackalloc byte[1];
                fs.ReadExactly(buffer);
                VERSION = buffer[0];

                VaultRegistry.GetVaultReader(VERSION).ReadVaultSession(fs);
            }
        }


        public void Dispose()
        {
            Array.Clear(KEY, 0, KEY.Length);
            Array.Clear(SALT, 0, SALT.Length);
            CryptographicOperations.ZeroMemory(KEY);
            CryptographicOperations.ZeroMemory(SALT);
            foreach (var item in ENCRYPTED_FILES)
            {
                ENCRYPTED_FILES[item.Key] = default;
            }
            ENCRYPTED_FILES.Clear();
            VAULTPATH = NormalizedPath.From(String.Empty);
            ITERATIONS = 0;
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
            Span<byte> buffer = stackalloc byte[32 + sizeof(uint)]; //Default salt size + 4 for uint ITERATIONS
            stream.ReadExactly(buffer);
            VaultSession.SALT = buffer[..32].ToArray();
            VaultSession.ITERATIONS = BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(32, sizeof(uint)));
            long[] offsets = ReadMetadataOffsets(stream);

            buffer = stackalloc byte[1024];
            foreach (var item in offsets)
            {
                stream.Seek(item, SeekOrigin.Begin);
                stream.ReadExactly(buffer);
                byte[] decrypted = VaultDecryption(buffer);
                byte version = decrypted[0];
                EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = EncryptionOptionsRegistry.GetReader(version).DeserializeEncryptionOptions(decrypted);
                VaultSession.ENCRYPTED_FILES.Add(item, fileEncryptionOptions);
            }
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
            return offsets;
        }

        internal virtual byte[] ReadMetadataOffsetsBytes(Stream stream)
        {
            stream.Seek(sizeof(byte) + 32 + sizeof(uint), SeekOrigin.Begin); //1 byte for version + 32 bytes for salt + 4 bytes for iterations
            Span<byte> buffer = stackalloc byte[28 + sizeof(ushort) + 4096]; //28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096) for maximum of 512 files per vault
            stream.ReadExactly(buffer);
            return VaultDecryption(buffer);
        }

        internal virtual void WriteMetadataOffsets(Stream stream, long newOffset)
        {
            long[] oldOffsets = ReadMetadataOffsets(stream);
            long[] newOffsets = new long[oldOffsets.Length + 1];
            Array.Copy(oldOffsets, newOffsets, oldOffsets.Length);
            newOffsets[oldOffsets.Length + 1] = newOffset;
            byte[] data = new byte[sizeof(ushort) + newOffsets.Length * sizeof(long)];
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0, sizeof(ushort)), (ushort)(newOffsets.Length));
            for (int i = 0; i < newOffsets.Length; i++)
            {
                int writeOffset = sizeof(ushort) + i * sizeof(long);
                BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(writeOffset, sizeof(long)), newOffsets[i]);
            }
            byte[] encryptedMetadataOffsets = Encryption.AesGcmEncryption.EncryptBytes(data, VaultSession.KEY);
            if (encryptedMetadataOffsets.Length > (28 + sizeof(ushort) + 4096))
            {
                throw new Exception("Too many files in the vault");
            }

            byte[] paddedMetadataOffsets = new byte[28 + sizeof(ushort) + 4096]; //28 bytes for AES encryption + 2 bytes ushort number + 4KB (4096) for maximum of 512 files per vault
            Buffer.BlockCopy(encryptedMetadataOffsets, 0, paddedMetadataOffsets, 0, encryptedMetadataOffsets.Length);

            stream.Seek(sizeof(byte) + 32 + sizeof(uint), SeekOrigin.Begin); //1 byte for version + 32 bytes for salt + 4 bytes for iterations
            stream.Write(paddedMetadataOffsets);
        }

        internal virtual byte[] VaultEncryption(byte[] data)
        {
            byte[] slicedKey = new byte[32];
            Array.Copy(VaultSession.KEY, slicedKey, slicedKey.Length);

            return Encryption.AesGcmEncryption.EncryptBytes(data, slicedKey);
        }

        internal virtual byte[] VaultDecryption(Span<byte> data)
        {
            byte[] slicedKey = new byte[32];
            Array.Copy(VaultSession.KEY, slicedKey, slicedKey.Length);

            return Decryption.AesGcmDecryption.DecryptBytes(data, slicedKey);
        }
    }






    internal class VaultV0Reader : VaultReader
    {
        internal override byte Version => 0;
    }








}
