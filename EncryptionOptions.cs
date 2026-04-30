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
        /// <br/>
        /// V1 = [version][nameLength][fileName][fileSize][encryptionAlgorithm][chunked][chunkInformation]
        /// Change: ChunkInformation holds number of chunks as ULong instead of UShort
        /// </summary>
        public record FileEncryptionOptions : IDisposable
        {
            public byte Version { get; private set; } //Fixed 1 byte, version of the FileEncryptionOptions
            public ushort NameLength { get; private set; } //Fixed 2 bytes, length of fileName text
            public SecureBuffer.SecureLargeBuffer FileName { get; private set; } //Varying length (read from nameLength), file name with extension!
            public ulong FileSize { get; private set; } //Fixed 8 bytes, Size in bytes of encrypted file, with extra encryption metadata
            public byte EncryptionAlgorithm { get; private set; } //Fixed 1 byte, Encryption algorithm ID
            public bool IsChunked { get; private set; } //Fixed 1 byte, Whether file is chunked or not
            public ChunkInformation? ChunkInformation { get; private set; } //Fixed 14 bytes (2 bytes chunk size + 8 bytes total chunks count + 4 bytes final chunk size)

            public FileEncryptionOptions(byte version, SecureBuffer.SecureLargeBuffer fileName, ulong fileSize, byte algorithm, bool chunked, ChunkInformation? chunkInformation)
            {
                try
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
                catch (Exception)
                {
                    fileName.Dispose();
                    throw;
                }
            }

            public FileEncryptionOptions(byte version, string fileName, ulong fileSize, byte algorithm, bool chunked, ChunkInformation? chunkInformation) : this(version, SetFileName(fileName), fileSize, algorithm, chunked, chunkInformation) { }

            /// <summary>
            /// Gets the filename as <see cref="string"/>
            /// </summary>
            /// <returns>String with the filename</returns>
            public string GetFileName()
            {
                return Encoding.UTF8.GetString(this.FileName.AsSpan);
            }

            private static SecureBuffer.SecureLargeBuffer SetFileName(string fileName)
            {
                var buffer = new SecureBuffer.SecureLargeBuffer(Encoding.UTF8.GetByteCount(fileName));
                Encoding.UTF8.GetBytes(fileName, buffer.AsSpan);

                return buffer;
            }

            public virtual bool Equals(FileEncryptionOptions? other)
            {
                if (other is null) return false;
                if (!FileName.AsSpan.SequenceEqual(other.FileName.AsSpan)) return false;
                if (ChunkInformation is not null) if (!ChunkInformation.Equals(other.ChunkInformation)) return false;
                return (Version == other.Version && NameLength == other.NameLength && FileSize == other.FileSize && EncryptionAlgorithm == other.EncryptionAlgorithm && IsChunked == other.IsChunked);
            }

            public override int GetHashCode()
            {
                HashCode hash = new HashCode();
                hash.Add(Version);
                hash.Add(NameLength);
                foreach (byte character in FileName.AsSpan) hash.Add(character);
                hash.Add(FileSize);
                hash.Add(EncryptionAlgorithm);
                hash.Add(IsChunked);
                hash.Add(ChunkInformation);
                return hash.ToHashCode();
            }

            private static void WriteFileEncryptionOptionsToSpan(FileEncryptionOptions encryptionOptions, Span<byte> span)
            {
                SpanWriter bufferSpan = new SpanWriter(span);
                bufferSpan.WriteByte(encryptionOptions.Version);
                bufferSpan.WriteUInt16(encryptionOptions.NameLength);
                bufferSpan.WriteSpan(encryptionOptions.FileName.AsSpan);
                bufferSpan.WriteUInt64(encryptionOptions.FileSize);
                bufferSpan.WriteByte(encryptionOptions.EncryptionAlgorithm);
                bufferSpan.WriteByte(encryptionOptions.IsChunked ? (byte)1 : (byte)0);
                if (encryptionOptions.IsChunked)
                {
                    using (SecureBuffer.SecureLargeBuffer chunkInfo = ChunkInformation.SerializeChunkInformation(encryptionOptions.ChunkInformation!))
                    {
                        bufferSpan.WriteSpan(chunkInfo.AsSpan);
                    }
                }
            }

            public static SecureBuffer.SecureLargeBuffer SerializeFileEncryptionOptions(FileEncryptionOptions encryptionOptions)
            {
                ArgumentNullException.ThrowIfNull(encryptionOptions);

                int resultSize = sizeof(byte) + sizeof(ushort) + encryptionOptions.NameLength + sizeof(ulong) + sizeof(byte) + sizeof(byte);
                if (encryptionOptions.IsChunked) resultSize += ChunkInformation.ChunkInformationSize;
                SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(resultSize);
                try
                {
                    WriteFileEncryptionOptionsToSpan(encryptionOptions, buffer.AsSpan);
                    return buffer;
                }
                catch (Exception)
                {
                    buffer.Dispose();
                    throw;
                }
            }

            public void Dispose()
            {
                Version = 0;
                FileName.Dispose();
                FileSize = 0;
                EncryptionAlgorithm = 0;
                IsChunked = false;
                ChunkInformation?.Dispose();
                ChunkInformation = null;
            }
        }

        public record ChunkInformation : IDisposable
        {
            public ushort ChunkSize { get; private set; } //Fixed 2 bytes, Chunk sizes in MB, without the extra encryption metadata
            public ulong TotalChunks { get; private set; } //Fixed 8 bytes, Number of chunks counting from 1
            public uint FinalChunkSize { get; private set; } //Fixed 4 bytes, Size in bytes of last chunk, without the extra encryption metadata

            public const int ChunkInformationSize = (sizeof(ushort) + sizeof(ulong) + sizeof(uint)); //Size of ChunkInformation in bytes
            public ChunkInformation(ushort chunkSize, ulong totalChunks, uint finalChunkSize)
            {
                this.ChunkSize = chunkSize;
                this.TotalChunks = totalChunks;
                this.FinalChunkSize = finalChunkSize;
            }

            public static SecureBuffer.SecureLargeBuffer SerializeChunkInformation(ChunkInformation chunkInformation)
            {
                SecureBuffer.SecureLargeBuffer chunkBytes = new SecureBuffer.SecureLargeBuffer(14);
                BinaryPrimitives.WriteUInt16LittleEndian(chunkBytes.AsSpan.Slice(0, 2), chunkInformation.ChunkSize);
                BinaryPrimitives.WriteUInt64LittleEndian(chunkBytes.AsSpan.Slice(2, 8), chunkInformation.TotalChunks);
                BinaryPrimitives.WriteUInt32LittleEndian(chunkBytes.AsSpan.Slice(10, 4), chunkInformation.FinalChunkSize);
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
                    1 => DeserializeV1(data),
                    _ => throw new VaultException(VaultException.ErrorContext.EncryptionOptions, VaultException.ErrorReason.NoReader)
                };
            }

            private static FileEncryptionOptions DeserializeV0(ReadOnlySpan<byte> data)
            {
                var spanReader = new SpanReader(data);
                byte version = spanReader.ReadByte();
                ushort nameLength = spanReader.ReadUInt16();
                SecureBuffer.SecureLargeBuffer fileName = spanReader.ReadBytes(nameLength);
                ulong fileSize = spanReader.ReadUInt64();
                byte encryptionAlgorithm = spanReader.ReadByte();
                bool chunked = spanReader.ReadByte() == 1 ? true : false;
                ChunkInformation? chunkInformation = null;
                if (chunked) chunkInformation = DeserializeChunkInformationV0(spanReader);
                return new FileEncryptionOptions(version, fileName, fileSize, encryptionAlgorithm, chunked, chunkInformation);
            }

            private static FileEncryptionOptions DeserializeV1(ReadOnlySpan<byte> data)
            {
                var spanReader = new SpanReader(data);
                byte version = spanReader.ReadByte();
                ushort nameLength = spanReader.ReadUInt16();
                SecureBuffer.SecureLargeBuffer fileName = spanReader.ReadBytes(nameLength);
                ulong fileSize = spanReader.ReadUInt64();
                byte encryptionAlgorithm = spanReader.ReadByte();
                bool chunked = spanReader.ReadByte() == 1 ? true : false;
                ChunkInformation? chunkInformation = null;
                if (chunked) chunkInformation = DeserializeChunkInformationV1(spanReader);
                return new FileEncryptionOptions(version, fileName, fileSize, encryptionAlgorithm, chunked, chunkInformation);
            }


            private static ChunkInformation DeserializeChunkInformationV0(SpanReader chunkData)
            {
                ushort chunkSize = chunkData.ReadUInt16();
                ushort totalChunks = chunkData.ReadUInt16();
                uint finalChunkSize = chunkData.ReadUInt32();
                return new ChunkInformation(chunkSize, totalChunks, finalChunkSize);
            }

            private static ChunkInformation DeserializeChunkInformationV1(SpanReader chunkData)
            {
                ushort chunkSize = chunkData.ReadUInt16();
                ulong totalChunks = chunkData.ReadUInt64();
                uint finalChunkSize = chunkData.ReadUInt32();
                return new ChunkInformation(chunkSize, totalChunks, finalChunkSize);
            }
        }
    }
}
