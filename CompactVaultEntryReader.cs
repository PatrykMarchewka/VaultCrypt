using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static VaultCrypt.CompactVaultEntry;

namespace VaultCrypt
{

    internal interface CompactVaultEntryReader
    {
        public CompactVaultEntry Read(Stream stream);
        public EncryptionHelper.EncryptionOptions ReadEncryptionOptions(Stream stream);
    }

    internal class ReaderFactory
    {
        public static CompactVaultEntryReader getReader(byte version)
        {
            return version switch
            {
                0 => new v0Reader(),
                _ => throw new NotSupportedException($"Version {version} is not supported")
            };
        }
    }

    internal class v0Reader : CompactVaultEntryReader
    {
        public CompactVaultEntry Read(Stream stream)
        {
            Span<byte> buffer = stackalloc byte[2];
            stream.ReadExactly(buffer);
            ushort nameLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer);

            byte[] nameBytes = new byte[nameLength];
            stream.ReadExactly(nameBytes);
            string fileName = Encoding.UTF8.GetString(nameBytes);

            buffer = stackalloc byte[8];
            stream.ReadExactly(buffer);
            ulong encLength = BinaryPrimitives.ReadUInt64LittleEndian(buffer);


            EncryptionHelper.EncryptionOptions options = ReadEncryptionOptions(stream);



            buffer = stackalloc byte[1];
            stream.ReadExactly(buffer);
            bool chunk = buffer[0] != 0;


            ChunkInformation? info = chunk ? ReadChunkInformation(stream) : null;

            return new CompactVaultEntry(nameLength: nameLength, fileName: fileName, fileSize: encLength, chunked: chunk, encryptionOptions: options, chunkInformation: info);
        }


        public EncryptionHelper.EncryptionOptions ReadEncryptionOptions(Stream stream)
        {
            Span<byte> buffer = stackalloc byte[2];
            stream.ReadExactly(buffer);
            ushort hashNameLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer);

            buffer = stackalloc byte[hashNameLength];
            stream.ReadExactly(buffer);
            HashAlgorithmName hash = HashAlgorithmName.FromOid(Encoding.UTF8.GetString(buffer));



            buffer = stackalloc byte[2];
            stream.ReadExactly(buffer);
            ushort saltLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer);

            buffer = stackalloc byte[saltLength];
            stream.ReadExactly(buffer);
            byte[] salt = buffer.ToArray();


            buffer = stackalloc byte[4];
            stream.ReadExactly(buffer);
            int iterations = BinaryPrimitives.ReadInt32LittleEndian(buffer);



            return new EncryptionHelper.EncryptionOptions(salt, hash, iterations);
        }

        static ChunkInformation ReadChunkInformation(Stream stream)
        {
            //2 bytes chunk size + 4 bytes total chunks count + 8 bytes final chunk size = 14 bytes
            Span<byte> buffer = stackalloc byte[14];
            stream.ReadExactly(buffer);

            ushort chunkSize = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(0, 2));
            uint totalChunks = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(2, 4));
            ulong finalChunkSize = BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(6, 8));
            if (finalChunkSize >= (ulong)(chunkSize * 1024 * 1024))
            {
                throw new Exception("Final chunk size bigger than normal chunk size");
            }

            return new ChunkInformation
            {
                chunkSize = chunkSize,
                totalChunks = totalChunks,
                finalChunkSize = finalChunkSize
            };
        }

    }
}
