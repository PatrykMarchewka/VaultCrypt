using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt
{
    public class EncryptionOptions
    {
        /// <summary>
        /// Record holding information about file that is either encrypted or about to be
        /// <br/>
        /// V0 = [version][nameLength][fileName][fileSize][encryptionAlgorithm][chunked][chunkInformation]
        /// </summary>
        public record FileEncryptionOptions : IDisposable
        {
            public byte Version { get; private set; } //Fixed 1 byte, version of the FileEncryptionOptions
            public ushort NameLength { get; private set; } //Fixed 2 bytes, length of fileName text
            public byte[] FileName { get; private set; } //Varying length (read from nameLength), file name with extension!
            public ulong FileSize { get; private set; } //Fixed 8 bytes, Size in bytes of encrypted file, with extra encryption metadata
            public byte EncryptionAlgorithm { get; private set; } //Fixed 1 byte, Encryption algorithm ID
            public bool IsChunked { get; private set; } //Fixed 1 byte, Whether file is chunked or not
            public ChunkInformation? ChunkInformation { get; private set; } //Fixed 8 bytes (2 bytes chunk size + 2 bytes total chunks count + 4 bytes final chunk size = 8 bytes)

            public FileEncryptionOptions(byte version, byte[] fileName, ulong fileSize, byte algorithm, bool chunked, ChunkInformation? chunkInformation)
            {
                if (chunked && chunkInformation is null) throw new ArgumentException("Chunk information cannot be null if chunk flag is set to true");

                Version = version;
                NameLength = checked((ushort)fileName.Length);
                FileName = fileName;
                FileSize = fileSize;
                EncryptionAlgorithm = algorithm;
                IsChunked = chunked;
                ChunkInformation = chunkInformation;
            }

            public virtual bool Equals(FileEncryptionOptions? other)
            {
                if (other is null) return false;
                if (!FileName.AsSpan().SequenceEqual(other.FileName)) return false;
                if (ChunkInformation is not null) if (!ChunkInformation.Equals(other.ChunkInformation)) return false;
                return (Version == other.Version && NameLength == other.NameLength && FileSize == other.FileSize && EncryptionAlgorithm == other.EncryptionAlgorithm && IsChunked == other.IsChunked);
            }

            public override int GetHashCode()
            {
                HashCode hash = new HashCode();
                hash.Add(Version);
                hash.Add(NameLength);
                foreach (byte character in FileName) hash.Add(character);
                hash.Add(FileSize);
                hash.Add(EncryptionAlgorithm);
                hash.Add(IsChunked);
                hash.Add(ChunkInformation);
                return hash.ToHashCode();
            }

            public static byte[] SerializeFileEncryptionOptions(FileEncryptionOptions encryptionOptions)
            {
                ArgumentNullException.ThrowIfNull(encryptionOptions);

                int resultSize = sizeof(byte) + sizeof(ushort) + encryptionOptions.NameLength + sizeof(long) + sizeof(byte) + sizeof(byte);
                if (encryptionOptions.IsChunked) resultSize += ChunkInformation.ChunkInformationSize;
                byte[] buffer = new byte[resultSize];
                try
                {
                    int currentOffset = 0;
                    buffer[currentOffset++] = encryptionOptions.Version;
                    BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(currentOffset, sizeof(ushort)), encryptionOptions.NameLength);
                    currentOffset += sizeof(ushort);
                    encryptionOptions.FileName.CopyTo(buffer.AsSpan(currentOffset));
                    currentOffset += encryptionOptions.NameLength;
                    BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(currentOffset, sizeof(long)), encryptionOptions.FileSize);
                    currentOffset += sizeof(long);
                    buffer[currentOffset++] = ((byte)encryptionOptions.EncryptionAlgorithm);
                    buffer[currentOffset++] = encryptionOptions.IsChunked ? (byte)1 : (byte)0;

                    if (encryptionOptions.IsChunked)
                    {
                        byte[] chunkInfo = null!;
                        try
                        {
                            chunkInfo = ChunkInformation.SerializeChunkInformation(encryptionOptions.ChunkInformation!);
                            Buffer.BlockCopy(chunkInfo, 0, buffer, currentOffset, chunkInfo.Length);
                        }
                        finally
                        {
                            if (chunkInfo is not null) CryptographicOperations.ZeroMemory(chunkInfo);
                        }
                    }
                    return buffer;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(buffer);
                    throw;
                }
            }

            public void Dispose()
            {
                Version = 0;
                CryptographicOperations.ZeroMemory(FileName);
                FileName = Array.Empty<byte>();
                FileSize = 0;
                EncryptionAlgorithm = 0;
                IsChunked = false;
                if (ChunkInformation is not null) ChunkInformation.Dispose();
                ChunkInformation = null;
            }
        }

        public record ChunkInformation : IDisposable
        {
            public ushort ChunkSize { get; private set; } //Fixed 2 bytes, Chunk sizes in MB, without the extra encryption metadata
            public ushort TotalChunks { get; private set; } //Fixed 2 bytes, Number of chunks counting from 1
            public uint FinalChunkSize { get; private set; } //Fixed 4 bytes, Size in bytes of last chunk, without the extra encryption metadata

            public const int ChunkInformationSize = (sizeof(ushort) + sizeof(ushort) + sizeof(uint)); //Size of ChunkInformation in bytes
            public ChunkInformation(ushort chunkSize, ushort totalChunks, uint finalChunkSize)
            {
                this.ChunkSize = chunkSize;
                this.TotalChunks = totalChunks;
                this.FinalChunkSize = finalChunkSize;
            }

            public static byte[] SerializeChunkInformation(ChunkInformation chunkInformation)
            {
                byte[] chunkBytes = new byte[8];
                BinaryPrimitives.WriteUInt16LittleEndian(chunkBytes.AsSpan(0, 2), chunkInformation.ChunkSize);
                BinaryPrimitives.WriteUInt16LittleEndian(chunkBytes.AsSpan(2, 2), chunkInformation.TotalChunks);
                BinaryPrimitives.WriteUInt32LittleEndian(chunkBytes.AsSpan(4, 4), chunkInformation.FinalChunkSize);
                return chunkBytes;
            }

            public void Dispose()
            {
                ChunkSize = 0;
                TotalChunks = 0;
                FinalChunkSize = 0;
            }
        }


        

        public class FileEncryptionOptionsReader
        {
            public static FileEncryptionOptions Deserialize(ReadOnlySpan<byte> data)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                byte version = data[0];

                return version switch
                {
                    0 => DeserializeV0(data),
                    _ => throw new VaultException(VaultException.ErrorContext.EncryptionOptions, VaultException.ErrorReason.NoReader)
                };
            }

            private static FileEncryptionOptions DeserializeV0(ReadOnlySpan<byte> data)
            {
                byte[] fileName = null!;
                var spanReader = new SpanReader(data);
                try
                {
                    byte version = spanReader.ReadByte();
                    ushort nameLength = spanReader.ReadUInt16();
                    fileName = spanReader.ReadBytes(nameLength);
                    ulong fileSize = spanReader.ReadUInt64();
                    byte encryptionAlgorithm = spanReader.ReadByte();
                    bool chunked = spanReader.ReadByte() == 1 ? true : false;
                    ChunkInformation? chunkInformation = null;
                    if (chunked) chunkInformation = DeserializeChunkInformationV0(spanReader);
                    return new FileEncryptionOptions(version, fileName.ToArray(), fileSize, encryptionAlgorithm, chunked, chunkInformation);
                }
                finally
                {
                    if (fileName is not null) CryptographicOperations.ZeroMemory(fileName);
                }
            }

            private static ChunkInformation DeserializeChunkInformationV0(SpanReader chunkData)
            {

                ushort chunkSize = chunkData.ReadUInt16();
                ushort totalChunks = chunkData.ReadUInt16();
                uint finalChunkSize = chunkData.ReadUInt32();
                return new ChunkInformation(chunkSize, totalChunks, finalChunkSize);
            }
        }

        
    }
}
