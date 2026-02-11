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
    internal class EncryptionOptions
    {
        /// <summary>
        /// Record holding information about file that is either encrypted or about to be
        /// <br/>
        /// V0 = [version][nameLength][fileName][fileSize][encryptionAlgorithm][chunked][chunkInformation]
        /// </summary>
        internal record FileEncryptionOptions : IDisposable
        {
            internal byte Version { get; private set; } //Fixed 1 byte, version of the FileEncryptionOptions
            internal ushort NameLength => checked((ushort)FileName.Length); //Fixed 2 bytes, length of fileName text
            internal byte[] FileName { get; private set; } //Varying length (read from nameLength), file name with extension!
            internal ulong FileSize { get; private set; } //Fixed 8 bytes, Size in bytes of encrypted file, with extra encryption metadata
            internal EncryptionAlgorithm.EncryptionAlgorithmEnum EncryptionAlgorithm { get; private set; } //Fixed 1 byte, Encryption algorithm enum
            internal bool IsChunked { get; private set; } //Fixed 1 byte, Whether file is chunked or not
            internal ChunkInformation? ChunkInformation { get; private set; } //Fixed 8 bytes (2 bytes chunk size + 2 bytes total chunks count + 4 bytes final chunk size = 8 bytes)

            internal FileEncryptionOptions(byte version, byte[] fileName, ulong fileSize, EncryptionAlgorithm.EncryptionAlgorithmEnum algorithm, bool chunked, ChunkInformation? chunkInformation)
            {
                Version = version;
                FileName = fileName;
                FileSize = fileSize;
                EncryptionAlgorithm = algorithm;
                IsChunked = chunked;
                ChunkInformation = chunkInformation;
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

        internal record ChunkInformation : IDisposable
        {
            internal ushort ChunkSize { get; private set; } //Fixed 2 bytes, Chunk sizes in MB, without the extra encryption metadata
            internal ushort TotalChunks { get; private set; } //Fixed 2 bytes, Number of chunks counting from 1
            internal uint FinalChunkSize { get; private set; } //Fixed 4 bytes, Size in bytes of last chunk, without the extra encryption metadata

            internal ChunkInformation(ushort chunkSize, ushort totalChunks, uint finalChunkSize)
            {
                this.ChunkSize = chunkSize;
                this.TotalChunks = totalChunks;
                this.FinalChunkSize = finalChunkSize;
            }

            public void Dispose()
            {
                ChunkSize = 0;
                TotalChunks = 0;
                FinalChunkSize = 0;
            }
        }


        

        internal static FileEncryptionOptions PrepareEncryptionOptions(FileInfo fileInfo, EncryptionAlgorithm.EncryptionAlgorithmEnum algorithm, ushort chunkSizeInMB)
        {
            ArgumentNullException.ThrowIfNull(fileInfo);
            ArgumentOutOfRangeException.ThrowIfZero(chunkSizeInMB);

            byte[] fileName = Encoding.UTF8.GetBytes(fileInfo.Name);
            bool chunked = false;
            ChunkInformation? chunkInformation = null;

            if (fileInfo.Length > (chunkSizeInMB * 1024 * 1024))
            {
                chunked = true;
                long chunkSize = chunkSizeInMB * 1024 * 1024;
                long chunkNumber = (fileInfo.Length / chunkSize) + 1;
                long lastChunk = fileInfo.Length - ((chunkNumber - 1) * chunkSize);
                //Handle the chunks are exactly dividing the full file case
                //Instead of producing empty last chunks it lowers the chunk count by one, after that the new last chunk is full sized one
                //Before: Chunk number = 4096, Last chunk size = 0 (Bytes read: 4096*1MB + 0) [Throws when reading/encrypting/decrypting due to 0 byte input/output]
                //After: Chunk number = 4095, Last chunk size = 1024 (Bytes read: 4095*1MB + 1MB)
                if (lastChunk == 0)
                {
                    chunkNumber--;
                    lastChunk = chunkSize;
                }
                chunkInformation = new ChunkInformation(chunkSizeInMB, checked((ushort)chunkNumber), checked((uint)lastChunk));
            }
            short extraBytes = EncryptionAlgorithm.GetEncryptionAlgorithmProvider[algorithm].EncryptionAlgorithm.ExtraEncryptionDataSize;

            ulong fileSize = chunkInformation is null ? (ulong)(fileInfo.Length + extraBytes) : (ulong)(fileInfo.Length + (extraBytes * chunkInformation.TotalChunks));
            return new FileEncryptionOptions(0, fileName, fileSize, algorithm, chunked, chunkInformation);
        }


        internal static byte[] EncryptAndPadFileEncryptionOptions(FileEncryptionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);



            VaultReader vaultReader = VaultSession.CurrentSession.VAULT_READER;
            byte[] encryptionOptionsBytes = null!;
            byte[] paddedFileOptions = new byte[vaultReader.EncryptionOptionsSize - EncryptionAlgorithm.GetEncryptionAlgorithmProvider[vaultReader.VaultEncryptionAlgorithm].EncryptionAlgorithm.ExtraEncryptionDataSize];
            try
            {
                encryptionOptionsBytes = SerializeEncryptionOptions(options);
                if ((encryptionOptionsBytes.Length + EncryptionAlgorithm.GetEncryptionAlgorithmProvider[vaultReader.VaultEncryptionAlgorithm].EncryptionAlgorithm.ExtraEncryptionDataSize) > vaultReader.EncryptionOptionsSize)
                {
                    throw new VaultException(VaultException.ErrorContext.EncryptionOptions, VaultException.ErrorReason.FileNameTooLong);
                }
                Buffer.BlockCopy(encryptionOptionsBytes, 0, paddedFileOptions, 0, encryptionOptionsBytes.Length);
            }
            finally
            {
                if (encryptionOptionsBytes is not null) CryptographicOperations.ZeroMemory(encryptionOptionsBytes);
            }
            byte[] encryptedFileOptions = null!;
            try
            {
                encryptedFileOptions = vaultReader.VaultEncryption(paddedFileOptions);
                return encryptedFileOptions;
            }
            catch(Exception)
            {
                if (encryptedFileOptions is not null) CryptographicOperations.ZeroMemory(encryptedFileOptions);
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(paddedFileOptions);
            }
        }

        private static byte[] SerializeEncryptionOptions(FileEncryptionOptions encryptionOptions)
        {
            ArgumentNullException.ThrowIfNull(encryptionOptions);

            int baseOptionsSize = sizeof(byte) + sizeof(ushort) + encryptionOptions.NameLength + sizeof(long) + sizeof(byte) + sizeof(byte);
            int chunkInfoSize = sizeof(ushort) + sizeof(ushort) + sizeof(uint);
            int resultSize = encryptionOptions.IsChunked ? (baseOptionsSize + chunkInfoSize) : baseOptionsSize;
            byte[] buffer = new byte[resultSize];
            try
            {
                int currentOffset = 0;
                buffer[currentOffset++] = 0;
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
                        chunkInfo = SerializeChunkInformation(encryptionOptions.ChunkInformation!);
                        Buffer.BlockCopy(chunkInfo, 0, buffer, currentOffset, chunkInfo.Length);
                    }
                    finally
                    {
                        if (chunkInfo is not null) CryptographicOperations.ZeroMemory(chunkInfo);
                    }
                }
                return buffer;
            }
            catch(Exception)
            {
                CryptographicOperations.ZeroMemory(buffer);
                throw;
            }
        }

        private static byte[] SerializeChunkInformation(ChunkInformation chunkInformation)
        {
            byte[] chunkBytes = new byte[8];
            BinaryPrimitives.WriteUInt16LittleEndian(chunkBytes.AsSpan(0, 2), chunkInformation.ChunkSize);
            BinaryPrimitives.WriteUInt16LittleEndian(chunkBytes.AsSpan(2, 2), chunkInformation.TotalChunks);
            BinaryPrimitives.WriteUInt32LittleEndian(chunkBytes.AsSpan(4, 4), chunkInformation.FinalChunkSize);
            return chunkBytes;
        }

        internal static FileEncryptionOptions GetDecryptedFileEncryptionOptions(Stream vaultFS, long metadataOffset)
        {
            VaultReader vaultReader = VaultSession.CurrentSession.VAULT_READER;
            byte[] decryptedMetadata = null!;
            FileEncryptionOptions fileEncryptionOptions = null!;
            try
            {
                decryptedMetadata = vaultReader.ReadAndDecryptData(vaultFS, metadataOffset, vaultReader.EncryptionOptionsSize);
                fileEncryptionOptions = Deserialize(decryptedMetadata);
            }
            catch(Exception)
            {
                if (fileEncryptionOptions is not null) fileEncryptionOptions.Dispose();
                throw;
            }
            finally
            {
                if (decryptedMetadata is not null) CryptographicOperations.ZeroMemory(decryptedMetadata);
            }
            return fileEncryptionOptions;
        }

        private static FileEncryptionOptions Deserialize(ReadOnlySpan<byte> data)
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
            try
            {
                int currentIndex = 0;
                byte version = data[currentIndex++];
                ushort nameLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(currentIndex, sizeof(ushort)));
                currentIndex += sizeof(ushort);
                fileName = data.Slice(currentIndex, nameLength).ToArray();
                currentIndex += nameLength;
                ulong fileSize = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(currentIndex, sizeof(ulong)));
                currentIndex += sizeof(ulong);
                EncryptionAlgorithm.EncryptionAlgorithmEnum encryptionAlgorithm = (EncryptionAlgorithm.EncryptionAlgorithmEnum)data[currentIndex++];
                bool chunked = data[currentIndex++] == 1 ? true : false;
                ChunkInformation? chunkInformation = null;
                if (chunked)
                {
                    chunkInformation = DeserializeChunkInformation(data[currentIndex..]);
                }
                return new FileEncryptionOptions(version, fileName.ToArray(), fileSize, encryptionAlgorithm, chunked, chunkInformation);
            }
            finally
            {
                if (fileName is not null) CryptographicOperations.ZeroMemory(fileName);
            }
        }

        private static ChunkInformation DeserializeChunkInformation(ReadOnlySpan<byte> chunkData)
        {
            if (chunkData.Length != (sizeof(ushort) + sizeof(ushort) + sizeof(uint))) throw new ArgumentOutOfRangeException("Provided wrong chunk information length");

            ushort chunkSize = BinaryPrimitives.ReadUInt16LittleEndian(chunkData.Slice(0, sizeof(ushort)));
            ushort totalChunks = BinaryPrimitives.ReadUInt16LittleEndian(chunkData.Slice(sizeof(ushort), sizeof(ushort)));
            uint finalChunkSize = BinaryPrimitives.ReadUInt32LittleEndian(chunkData.Slice(sizeof(ushort) + sizeof(ushort), sizeof(uint)));
            return new ChunkInformation(chunkSize, totalChunks, finalChunkSize);
        }
    }
}
