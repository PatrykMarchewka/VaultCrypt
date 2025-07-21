using Microsoft.VisualBasic;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Printing.IndexedProperties;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class CompactVaultEntry
    {
        //byte = 1 byte | 0 to 255
        //ushort = 2 bytes | 0 to 65 535
        //uint = 4 bytes | 0 to 4 294 967 295
        //ulong = 8 bytes | 0 to 1.8 * 10^19
        public static byte nameLengthSize = 2;
        public static byte fileSizeSize = 8;
        public static byte chunkedSize = 1;
        public static byte versionSize = 1;
        public static byte chunkInformationSize = 14; //2 bytes chunk size + 4 bytes total chunks count + 8 bytes final chunk size = 14 bytes
        

        public ushort nameLength { get; init; } //Fixed 2 bytes, length of fileName text
        public string fileName { get; init; } //Varying length, read from nameLength
        public ulong fileSize { get; init; } //Size of encrypted file
        public bool chunked { get; init; } //Whether file is chunked or not
        public byte version { get; init; } //Version of the CompactVaultEntry
        public EncryptionHelper.EncryptionOptions encryptionOptions { get; init; }
        public ChunkInformation? chunkInformation { get; init; }
        


        public CompactVaultEntry(ushort nameLength, string fileName, ulong fileSize, bool chunked, EncryptionHelper.EncryptionOptions encryptionOptions, ChunkInformation? chunkInformation)
        {
            this.nameLength = nameLength;
            this.fileName = fileName;
            this.fileSize = fileSize;
            this.chunked = chunked;
            this.version = 0;
            this.encryptionOptions = encryptionOptions;
            this.chunkInformation = chunkInformation;
        }

        

        static void WriteEncryptionOptions(EncryptionHelper.EncryptionOptions encryptionOptions, Stream stream)
        {
            Span<byte> buffer = stackalloc byte[2];
            byte[] hashNameBytes = Encoding.UTF8.GetBytes(encryptionOptions.HashAlgorithm.Name);
            BinaryPrimitives.WriteUInt16LittleEndian(buffer, (ushort)hashNameBytes.Length);
            stream.Write(buffer);
            stream.Write(hashNameBytes);

            buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(buffer, (ushort)encryptionOptions.Salt.Length);
            stream.Write(buffer);
            stream.Write(encryptionOptions.Salt);

            buffer = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(buffer, encryptionOptions.Iterations);
            stream.Write(buffer);
        }


        public struct ChunkInformation
        {
            public ushort chunkSize { get; init; } //chunk sizes in MB
            public uint totalChunks { get; init; } //number of chunks
            public ulong finalChunkSize { get; init; } //size in bytes of last chunk

            public ChunkInformation(ushort chunkSize, uint totalChunks, ulong finalChunkSize)
            {
                this.chunkSize = chunkSize;
                this.totalChunks = totalChunks;
                this.finalChunkSize = finalChunkSize;
            }
        }


        public static void WriteChunkInformation(ChunkInformation chunk, Stream stream)
        {
            Span<byte> buffer = stackalloc byte[chunkInformationSize];

            BinaryPrimitives.WriteUInt16LittleEndian(buffer.Slice(0, 2), chunk.chunkSize);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(2, 4), chunk.totalChunks);
            BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(6, 8), chunk.finalChunkSize);
            stream.Write(buffer);
        }



        public static CompactVaultEntry ReadFrom(Stream stream)
        {
            Span<byte> buffer = stackalloc byte[1];
            stream.ReadExactly(buffer);
            byte version = buffer[0];

            return ReaderFactory.getReader(version).Read(stream);
        }


        public static void WriteTo(CompactVaultEntry entry, Stream stream)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(entry.fileName);
            if (nameBytes.Length > ushort.MaxValue)
            {
                throw new Exception("File name is too long!");
            }
            stream.WriteByte(entry.version);


            Span<byte> buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(buffer, (ushort)nameBytes.Length);
            stream.Write(buffer);

            stream.Write(nameBytes);

            buffer = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(buffer, entry.fileSize);
            stream.Write(buffer);

            WriteEncryptionOptions(entry.encryptionOptions, stream);


            stream.WriteByte(entry.chunked ? (byte)1 : (byte)0);


            if (entry.chunked)
            {
                if (entry.chunkInformation == null)
                {
                    throw new Exception("Entry is chunked yet there is no chunk information");
                }
                WriteChunkInformation(entry.chunkInformation.Value, stream);
                
            }
            
        }


    }




    internal class VaultEntry
    {
        public long compactVaultEntryOffset { get; set; } //Has to point to beginning of the CompactVaultEntry, not File itself!
        public long fileSize { get; set; } //Size of encrypted file
        public DateTime creationDateUTC { get; set; } = DateTime.UtcNow;
        public NormalizedPath? originalPath { get; set; }
        public VaultContentType contentType { get; set; }
        

        public enum VaultContentType
        {
            Unknown,
            Text,
            Image,
            Audio,
            Video,
            Archive,
            Executable,
            Document
        }

        public static VaultContentType GetContentTypeFromExtension(NormalizedPath filepath)
        {
            string ext = Path.GetExtension(filepath).ToLowerInvariant();
            return ext switch
            {
                ".txt" => VaultContentType.Text,
                ".jpg" or ".jpeg" or ".png" or ".bmp" => VaultContentType.Image,
                ".mp3" or ".wav" => VaultContentType.Audio,
                ".mp4" or ".mov" => VaultContentType.Video,
                ".zip" or ".rar" or ".7z" => VaultContentType.Archive,
                ".exe" or ".msi" => VaultContentType.Executable,
                ".pdf" or ".docx" or ".doc" => VaultContentType.Document,
                _ => VaultContentType.Unknown
            };
        }
    }

    internal class IndexMetadata
    {
        public Dictionary<string, VaultEntry> meta { get; set; } = new Dictionary<string, VaultEntry>();
        string formatVersion { get; set; } = "v1.0";
    }
}
