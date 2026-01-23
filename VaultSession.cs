using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.ViewModels;

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
                VaultHelper.RefreshEncryptedFilesList(fs);
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

        internal static void RefreshEncryptedFilesList(Stream vaultFS)
        {
            VaultSession.ENCRYPTED_FILES.Clear();
            VaultRegistry.GetVaultReader(VaultSession.VERSION).ReadVaultSession(vaultFS);
            OpenVaultViewModel.EncryptedFilesCollectionView.Refresh();
        }



        public class ProgressionContext : INotifyPropertyChanged
        {
            private int _completed;
            public int Completed
            {
                get => _completed;
                set
                {
                    if (_completed == value) return;
                    _completed = value;
                    OnPropertyChanged(nameof(Completed));
                }
            }
            private int _total;
            public int Total
            {
                get => _total;
                set
                {
                    if (_total == value) return;
                    _total = value;
                    OnPropertyChanged(nameof(Total));
                }
            }
            public IProgress<ProgressStatus> Progress { get; init; }
            public CancellationTokenSource CancellationTokenSource;



            public CancellationToken CancellationToken => CancellationTokenSource.Token;

            public ProgressionContext()
            {
                Completed = 0;
                Total = 0;
                CancellationTokenSource = new CancellationTokenSource();
                Progress = new Progress<ProgressStatus>(p => { Completed = p.completed; Total = p.total; });
            }
            private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
            public event PropertyChangedEventHandler? PropertyChanged;
        }

        internal record ProgressStatus(int completed, int total);
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
        internal virtual short SaltSize => 32; //Size in bytes of the salt
        internal virtual short EncryptionOptionsSize => 1024; //Size of already encrypted EncryptionOptions
        internal virtual short MetadataOffsetsSize => 4096; //Size of metadata offsets collection before encryption
        internal virtual short HeaderSize => (short)(1 + SaltSize + sizeof(int) + EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].encryptionDataSize + sizeof(ushort) + MetadataOffsetsSize); //Full size of vault header



        internal virtual void ReadVaultSession(Stream stream)
        {
            long[] offsets = ReadMetadataOffsets(stream);
            foreach (long offset in offsets)
            {
                byte[] decrypted = ReadAndDecryptData(stream, offset, EncryptionOptionsSize);
                EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = EncryptionOptionsRegistry.GetReader(decrypted[0]).DeserializeEncryptionOptions(decrypted); ;
                CryptographicOperations.ZeroMemory(decrypted);
                VaultSession.ENCRYPTED_FILES.Add(offset, Encoding.UTF8.GetString(fileEncryptionOptions.fileName));
                EncryptionOptions.WipeFileEncryptionOptions(ref fileEncryptionOptions);
            }
        }

        internal byte[] ReadAndDecryptData(Stream stream, long offset, int length)
        {
            byte[] buffer = new byte[length];
            stream.Seek(offset, SeekOrigin.Begin);
            stream.ReadExactly(buffer, 0, length);
            byte[] decrypted = VaultDecryption(buffer);
            CryptographicOperations.ZeroMemory(buffer);
            return decrypted;
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

        private long[] ReadMetadataOffsets(Stream stream)
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
        internal virtual void AddAndSaveMetadataOffsets(Stream stream, long newOffset)
        {
            long[] oldOffsets = ReadMetadataOffsets(stream);
            if (oldOffsets.Length + 1 > (sizeof(ushort) + MetadataOffsetsSize))
            {
                throw new Exception("Too many files in the vault");
            }
            long[] newOffsets = new long[oldOffsets.Length + 1];
            oldOffsets.AsSpan().CopyTo(newOffsets);
            newOffsets[oldOffsets.Length] = newOffset;
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(oldOffsets.AsSpan()));
            SaveMetadataOffsets(stream, newOffsets);
        }

        /// <summary>
        /// Removes offset at specified index and writes encrypted offsest to vault
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="itemIndex"></param>
        internal void RemoveAndSaveMetadataOffsets(Stream stream, ushort itemIndex)
        {
            long[] oldOffsets = ReadMetadataOffsets(stream);
            long[] newOffsets = oldOffsets.Where((offset, index) => index != itemIndex).ToArray();
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(oldOffsets.AsSpan()));
            SaveMetadataOffsets(stream, newOffsets);
        }

        internal virtual byte[] PrepareMetadataOffsets(long[] offsets)
        {
            byte[] offsetsBytes = new byte[sizeof(ushort) + (offsets.Length * sizeof(long))];
            Buffer.BlockCopy(offsets, 0, offsetsBytes, sizeof(ushort), offsets.Length * sizeof(long));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(offsets.AsSpan()));
            BinaryPrimitives.WriteUInt16LittleEndian(offsetsBytes.AsSpan(0, sizeof(ushort)), (ushort)(offsets.Length));
            return offsetsBytes;
        }

        internal void SaveMetadataOffsets(Stream stream, long[] offsets)
        {
            byte[] offsetsBytes = PrepareMetadataOffsets(offsets);
            byte[] encryptedMetadataOffsets = PadMetadataOffsetsAndEncrypt(offsetsBytes);
            CryptographicOperations.ZeroMemory(offsetsBytes);
            WriteMetadataOffsets(stream, encryptedMetadataOffsets);
            CryptographicOperations.ZeroMemory(encryptedMetadataOffsets);
        }

        /// <summary>
        /// Pads supplied <paramref name="metadataOffsets"/> to <see cref="MetadataOffsetsSize"/> and encrypts the entire collection
        /// </summary>
        /// <param name="metadataOffsets"></param>
        /// <returns></returns>
        private byte[] PadMetadataOffsetsAndEncrypt(byte[] metadataOffsets)
        {
            byte[] paddedMetadataOffsets = new byte[sizeof(ushort) + MetadataOffsetsSize]; //2 bytes ushort for number of currently attached offsets
            Buffer.BlockCopy(metadataOffsets, 0, paddedMetadataOffsets, 0, metadataOffsets.Length);
            CryptographicOperations.ZeroMemory(metadataOffsets);
            byte[] encryptedMetadataOffsets = VaultEncryption(paddedMetadataOffsets);
            CryptographicOperations.ZeroMemory(paddedMetadataOffsets);
            return encryptedMetadataOffsets;
        }

        internal virtual void WriteMetadataOffsets(Stream stream, byte[] encryptedMetadataOffsets)
        {
            stream.Seek(sizeof(byte) + SaltSize + sizeof(uint), SeekOrigin.Begin); //1 byte for version + bytes for salt + 4 bytes for iterations
            stream.Write(encryptedMetadataOffsets);
        }

        internal virtual byte[] VaultEncryption(byte[] data)
        {
            byte[] slicedKey = new byte[EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].keySize];
            Buffer.BlockCopy(VaultSession.KEY, 0, slicedKey, 0, slicedKey.Length);

            return Encryption.AesGcmEncryption.EncryptBytes(data, slicedKey);
        }

        internal virtual byte[] VaultDecryption(Span<byte> data)
        {
            byte[] slicedKey = new byte[EncryptionOptions.GetEncryptionProtocolInfo[EncryptionProtocol].keySize];
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
