using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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


                switch (VERSION)
                {
                    case 0:
                        VaultV0Reader.ReadVaultSession(fs);
                        break;
                    default:
                        throw new Exception("Unknown vault version");
                }
            }
        }


        public void Dispose()
        {
            Array.Clear(KEY, 0, KEY.Length);
            Array.Clear(SALT, 0, SALT.Length);
            ENCRYPTED_FILES.Clear();
            VAULTPATH = NormalizedPath.From(String.Empty);
            ITERATIONS = 0;
        }
    }

    internal class VaultV0Reader
    {
        public static void ReadVaultSession(Stream stream)
        {
            Span<byte> buffer = stackalloc byte[32 + sizeof(uint)]; //Default salt size + 4 for uint ITERATIONS
            stream.ReadExactly(buffer);
            VaultSession.SALT = buffer[..32].ToArray();
            VaultSession.ITERATIONS = BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(32, sizeof(uint)));
            long[] offsets = ReadMetadataOffsets(stream);

            foreach (var item in offsets)
            {
                stream.Seek(item, SeekOrigin.Begin);
                buffer = stackalloc byte[1024];
                stream.ReadExactly(buffer);
                byte[] decrypted = Decryption.AesGcmDecryption.DecryptBytes(buffer);
                EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = EncryptionOptions.DeserializeEncryptionOptions(decrypted);
                VaultSession.ENCRYPTED_FILES.Add(item, fileEncryptionOptions);
            }
        }

        public static long[] ReadMetadataOffsets(Stream stream)
        {
            byte[] decrypted = ReadMetadataOffsetsBytes(stream);
            ushort fileCount = BinaryPrimitives.ReadUInt16LittleEndian(decrypted);

            long[] offsets = new long[fileCount];
            for (int i = 0; i < fileCount; i++)
            {
                int readOffset = 2 + (i * sizeof(long));
                offsets[i] = BinaryPrimitives.ReadInt64LittleEndian(decrypted.AsSpan(readOffset,sizeof(long)));
            }
            return offsets;
        }

        public static byte[] ReadMetadataOffsetsBytes(Stream stream)
        {
            stream.Seek(sizeof(byte) + 32 + sizeof(uint), SeekOrigin.Begin); //1 byte for version + 32 bytes for salt + 4 bytes for iterations
            Span<byte> buffer = stackalloc byte[28 + sizeof(ushort) + 4096]; //28 bytes for AES decryption + 2 bytes ushort number + 4KB (4096) for maximum of 512 files per vault
            stream.ReadExactly(buffer);
            return Decryption.AesGcmDecryption.DecryptBytes(buffer);
        }

        public static void WriteMetadataOffsets(Stream stream, long newOffset)
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
            byte[] paddedMetadataOffsets = new byte[28 + sizeof(ushort) + 4096]; //28 bytes for AES encryption + 2 bytes ushort number + 4KB (4096) for maximum of 512 files per vault
            Buffer.BlockCopy(encryptedMetadataOffsets, 0, paddedMetadataOffsets, 0, encryptedMetadataOffsets.Length);

            stream.Seek(sizeof(byte) + 32 + sizeof(uint), SeekOrigin.Begin); //1 byte for version + 32 bytes for salt + 4 bytes for iterations
            stream.Write(paddedMetadataOffsets);
        }
    }








}
