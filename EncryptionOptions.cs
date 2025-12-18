using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class EncryptionOptions
    {
        /// <summary>
        /// Pad it out to 1024Bytes
        /// </summary>
        internal struct FileEncryptionOptions
        {
            //byte = 1 byte | 0 to 255
            //ushort = 2 bytes | 0 to 65 535
            //uint = 4 bytes | 0 to 4 294 967 295
            //ulong = 8 bytes | 0 to 1.8 * 10^19
            internal byte version { get; init; } //Fixed 1 byte, version of the FileEncryptionOptions
            internal ushort nameLength { get; init; } //Fixed 2 bytes, length of fileName text
            internal string fileName { get; init; } //Varying length (read from nameLength), file name with extension, 255 characters max! so 1020bytes max
            internal ulong fileSize { get; init; } //Fixed 8 bytes, Size in bytes of encrypted file
            internal EncryptionProtocol encryptionProtocol { get; init; } //Fixed 1 byte, Encryption protocol enum
            internal bool chunked { get; init; } //Fixed 1 byte, Whether file is chunked or not
            internal ChunkInformation? chunkInformation { get; init; } //Fixed 8 bytes (2 bytes chunk size + 2 bytes total chunks count + 4 bytes final chunk size = 8 bytes)

            //V0 = [version][nameLength][fileName][fileSize][encryptionProtocol][chunked][chunkInformation]
        }

        internal struct ChunkInformation
        {
            internal ushort chunkSize { get; init; } //Fixed 2 bytes, Chunk sizes in MB
            internal ushort totalChunks { get; init; } //Fixed 2 bytes, Number of chunks
            internal uint finalChunkSize { get; init; } //Fixed 4 bytes, Size in bytes of last chunk

            internal ChunkInformation(ushort chunkSize, ushort totalChunks, uint finalChunkSize)
            {
                this.chunkSize = chunkSize;
                this.totalChunks = totalChunks;
                this.finalChunkSize = finalChunkSize;
            }
        }


        internal enum EncryptionProtocol : byte
        {
            AES128GCM,
            AES192GCM,
            AES256GCM
        }

        internal static readonly Dictionary<EncryptionProtocol, (byte keySize, short encryptionDataSize, Func<byte[], byte[], byte[]> encryptMethod, Func<byte[], byte[], byte[]> decryptMethod)> GetEncryptionProtocolInfo = new()
        {
            {EncryptionProtocol.AES128GCM, (keySize: 16, encryptionDataSize: 28, encryptMethod: (data, key) => Encryption.AesGcmEncryption.EncryptBytes(data, key), decryptMethod: (data, key) => Decryption.AesGcmDecryption.DecryptBytes(data, key)) },
            {EncryptionProtocol.AES192GCM, (keySize: 24, encryptionDataSize: 28, encryptMethod: (data, key) => Encryption.AesGcmEncryption.EncryptBytes(data, key), decryptMethod: (data, key) => Decryption.AesGcmDecryption.DecryptBytes(data, key)) },
            {EncryptionProtocol.AES256GCM, (keySize:32, encryptionDataSize: 28, encryptMethod: (data, key) => Encryption.AesGcmEncryption.EncryptBytes(data, key), decryptMethod: (data, key) => Decryption.AesGcmDecryption.DecryptBytes(data, key)) }
        };

        {


            {
            };
        }



        internal static byte[] SerializeEncryptionOptions(EncryptionOptions.FileEncryptionOptions encryptionOptions)
        {
            List<byte> bytes = new();
            byte[] buffer = new byte[sizeof(byte) + sizeof(ushort) + encryptionOptions.nameLength + sizeof(long) + sizeof(byte) + sizeof(byte)]; //1 byte version, 2 byte name length, x bytes name, 8 bytes size, 1 byte encryptionprotocol, 1 byte chunkinformation
            buffer[0] = 0;
            BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(sizeof(byte), sizeof(ushort)), encryptionOptions.nameLength);
            Encoding.UTF8.GetBytes(encryptionOptions.fileName).CopyTo(buffer.AsSpan(sizeof(byte) + sizeof(ushort)));
            BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(sizeof(byte) + sizeof(ushort) + encryptionOptions.nameLength, sizeof(long)), encryptionOptions.fileSize);
            buffer[sizeof(byte) + sizeof(ushort) + encryptionOptions.nameLength + sizeof(long)] = ((byte)encryptionOptions.encryptionProtocol);
            buffer[sizeof(byte) + sizeof(ushort) + encryptionOptions.nameLength + sizeof(long) + sizeof(byte)] = encryptionOptions.chunked ? (byte)1 : (byte)0;

            bytes.AddRange(buffer);
            if (encryptionOptions.chunked)
            {
                bytes.AddRange(SerializeChunkInformation((EncryptionOptions.ChunkInformation)encryptionOptions.chunkInformation!));
            }
            return bytes.ToArray();
        }

        internal static byte[] SerializeChunkInformation(EncryptionOptions.ChunkInformation chunkInformation)
        {
            byte[] chunkBytes = new byte[8];
            BinaryPrimitives.WriteUInt16LittleEndian(chunkBytes.AsSpan(0, 2), chunkInformation.chunkSize);
            BinaryPrimitives.WriteUInt32LittleEndian(chunkBytes.AsSpan(2, 2), chunkInformation.totalChunks);
            BinaryPrimitives.WriteUInt64LittleEndian(chunkBytes.AsSpan(4, 4), chunkInformation.finalChunkSize);
            return chunkBytes;
        }
    }

    internal static class EncryptionOptionsRegistry
    {
        private readonly static Dictionary<byte, EncryptionOptionsReader> registry = new()
        {
            {0, new EncryptionOptionsV0Reader() }
        };

        internal static EncryptionOptionsReader GetReader(byte version)
        {
            if (!registry.TryGetValue(version, out EncryptionOptionsReader reader))
            {
                throw new Exception("Unknown encryption options version");
            }
            return reader;
        }
    }



    internal abstract class EncryptionOptionsReader
    {
        internal abstract byte Version { get; }

        internal virtual EncryptionOptions.FileEncryptionOptions DeserializeEncryptionOptions(byte[] data)
        {
            byte version = data[0];
            ushort nameLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(1, sizeof(ushort)));
            string fileName = Encoding.UTF8.GetString(data.AsSpan(1 + sizeof(ushort), nameLength));
            ulong fileSize = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(1 + sizeof(ushort) + nameLength, sizeof(ulong)));
            EncryptionOptions.EncryptionProtocol protocol = (EncryptionOptions.EncryptionProtocol)data[1 + sizeof(ushort) + nameLength + sizeof(ulong)];
            bool chunked = data[1 + sizeof(ushort) + nameLength + sizeof(ulong) + 1] == 1 ? true : false;
            EncryptionOptions.ChunkInformation? chunkInformation = null;
            if (chunked)
            {
                chunkInformation = DeserializeChunkInformation(data.AsSpan(1 + sizeof(ushort) + nameLength + sizeof(ulong) + 1 + 1).ToArray());
            }


            return new EncryptionOptions.FileEncryptionOptions
            {
                version = version,
                nameLength = nameLength,
                fileName = fileName,
                fileSize = fileSize,
                encryptionProtocol = protocol,
                chunked = chunked,
                chunkInformation = chunkInformation
            };
        }

        internal virtual EncryptionOptions.ChunkInformation DeserializeChunkInformation(byte[] chunkData)
        {
            ushort chunkSize = BinaryPrimitives.ReadUInt16LittleEndian(chunkData.AsSpan(0, sizeof(ushort)));
            ushort totalChunks = BinaryPrimitives.ReadUInt16LittleEndian(chunkData.AsSpan(sizeof(ushort), sizeof(ushort)));
            uint finalChunkSize = BinaryPrimitives.ReadUInt32LittleEndian(chunkData.AsSpan(sizeof(ushort) + sizeof(ushort), sizeof(uint)));

            return new EncryptionOptions.ChunkInformation
            {
                chunkSize = chunkSize,
                totalChunks = totalChunks,
                finalChunkSize = finalChunkSize
            };
        }


        internal static FileEncryptionOptions PrepareEncryptionOptions(FileInfo fileInfo, EncryptionProtocol protocol, int chunkSizeInMB)
        {
            ushort nameLength = (ushort)(fileInfo.Name.Length);
            string fileName = fileInfo.Name;
            bool chunked = false;
            ChunkInformation? chunkInformation = null;

            if (fileInfo.Length > chunkSizeInMB)
            {
                chunked = true;
                long chunkSize = chunkSizeInMB * 1024 * 1024;
                long chunkNumber = (fileInfo.Length / chunkSize) + 1;
                long lastChunk = fileInfo.Length - ((chunkNumber - 1) * chunkSize);
                chunkInformation = new ChunkInformation((ushort)chunkSizeInMB, (uint)chunkNumber, (ulong)lastChunk);
            }
            short extraBytes = GetEncryptionDataSizeByEncryptionProtocol(protocol);

            ulong fileSize = chunkInformation == null ? (ulong)(fileInfo.Length + extraBytes) : (ulong)(fileInfo.Length + extraBytes + (extraBytes * chunkInformation.Value.totalChunks));
            return new FileEncryptionOptions
            {
                version = 0,
                nameLength = nameLength,
                fileName = fileName,
                fileSize = fileSize,
                encryptionProtocol = protocol,
                chunked = chunked,
                chunkInformation = chunkInformation
            };
        }
    }
}
