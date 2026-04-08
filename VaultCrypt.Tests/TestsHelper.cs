using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using VaultCrypt.Services;

namespace VaultCrypt.Tests
{
    /// <summary>
    /// Class designated to hold helper methods for testing.
    /// Helper methods are intended to work WITHOUT relying on external sources such as services on purpose
    /// </summary>
    internal class TestsHelper
    {

        /// <summary>
        /// Creates temporary file filled with random bytes
        /// </summary>
        /// <param name="size">Size of the file to create</param>
        /// <returns>Path to the temporary file</returns>
        internal static NormalizedPath CreateTemporaryFile(int size)
        {
            var path = Path.GetTempFileName();
            File.WriteAllBytes(path, RandomNumberGenerator.GetBytes(size));
            return NormalizedPath.From(path);
        }

        /// <summary>
        /// Creates empty instance of VaultSession using reflection to bypass private constructor
        /// </summary>
        /// <returns>New instance of VaultSession</returns>
        internal static VaultSession CreateEmptySessionInstance()
        {
            return (VaultSession)Activator.CreateInstance(typeof(VaultSession), nonPublic: true)!;
        }

        /// <summary>
        /// Creates instance of VaultSession and fills it with provided values or predetermined default ones using reflection to bypass private constructor and field setters <br/>
        /// Created instance uses <see cref="FakeVaultReader"/> by default, you can pass your own reader or use <see cref="CreateFilledSessionInstanceWithReader(ReadOnlySpan{byte}, byte, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?)"/> instead
        /// </summary>
        /// <param name="key"></param>
        /// <param name="vaultPath"></param>
        /// <param name="encryptedFiles"></param>
        /// <param name="vaultReader"></param>
        /// <returns>New instance of VaultSession with filled attributes</returns>
        internal static VaultSession CreateFilledSessionInstance(ReadOnlySpan<byte> key, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null, IVaultReader? vaultReader = null)
        {
            NormalizedPath vaultPathDefault = NormalizedPath.From("C:\\FilledSessionInstance\\");
            Dictionary<long, EncryptedFileInfo> encryptedFilesDefault = new()
            {
                {0, new EncryptedFileInfo(null, 0, null) },
                {1, new EncryptedFileInfo("secret.pdf", 1_234, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0]) },
                {10, new EncryptedFileInfo("anotherone.mp3", 12_345, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[1]) }
            };
            IVaultReader readerDefault = new FakeVaultReader();

            var session = (VaultSession)Activator.CreateInstance(typeof(VaultSession), nonPublic: true)!;
            SecureBuffer.SecureKeyBuffer keyBuffer = new SecureBuffer.SecureKeyBuffer(PasswordHelper.KeySize);
            key.CopyTo(keyBuffer.AsSpan);
            typeof(VaultSession).GetProperty(nameof(VaultSession.KEY))!.SetValue(session, keyBuffer);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULTPATH))!.SetValue(session, vaultPath ?? vaultPathDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.ENCRYPTED_FILES))!.SetValue(session, encryptedFiles ?? encryptedFilesDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULT_READER))!.SetValue(session, vaultReader ?? readerDefault);

            return session;
        }

        /// <summary>
        /// Calls internal <see cref="CreateFilledSessionInstance(ReadOnlySpan{byte}, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?, IVaultReader?)"/> but replaces fake reader with real one utilizing newest vault version
        /// </summary>
        /// <param name="key"></param>
        /// <param name="vaultPath"></param>
        /// <param name="encryptedFiles"></param>
        /// <returns>New instance of VaultSession with filled attributes</returns>
        internal static VaultSession CreateFilledSessionInstanceWithReader(ReadOnlySpan<byte> key, byte version = VaultSession.NewestVaultVersion, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null)
        {
            var session = CreateFilledSessionInstance(key, vaultPath, encryptedFiles, null);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULT_READER))!.SetValue(session, CreateVaultRegistry(session).GetVaultReader(VaultSession.NewestVaultVersion));
            return session;
        }

        /// <summary>
        /// Calls internal <see cref="CreateFilledSessionInstanceWithReader(ReadOnlySpan{byte}, byte, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?)"/> and replaces fake reader with real one utilizing newest vault version
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="iterations"></param>
        /// <param name="version"></param>
        /// <param name="vaultPath"></param>
        /// <param name="encryptedFiles"></param>
        /// <param name="vaultReader"></param>
        /// <returns></returns>
        internal static VaultSession CreateFilledSessionInstanceWithReader(byte[]? password = null, byte[]? salt = null, int iterations = 1000, byte version = VaultSession.NewestVaultVersion, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null, IVaultReader? vaultReader = null)
        {
            password ??= new byte[16];
            salt ??= new byte[32];
            ReadOnlySpan<byte> key = CreateKey(password, salt, iterations);
            return CreateFilledSessionInstanceWithReader(key, version, vaultPath, encryptedFiles);
        }

        /// <summary>
        /// Replaces values in <paramref name="session"/> with new ones read from <paramref name="vaultFS"/>
        /// </summary>
        /// <param name="session">Session to edit values of</param>
        /// <param name="vaultFS">Stream to read new values from</param>
        /// <param name="password">Password to decrypt data</param>
        /// <returns>Session with new values</returns>
        internal static IVaultSession SetVaultSessionFromStream(IVaultSession session, Stream vaultFS, byte[]? password = null)
        {
            vaultFS.Seek(0, SeekOrigin.Begin);

            byte version = (byte)vaultFS.ReadByte();
            IVaultReader reader =  CreateVaultRegistry(session).GetVaultReader(version);
            byte[] salt = new byte[session.VAULT_READER.SaltSize];
            vaultFS.Read(salt);
            byte[] iterationBytes = new byte[4];
            vaultFS.Read(iterationBytes);
            int iterations = BinaryPrimitives.ReadInt32LittleEndian(iterationBytes);
            NormalizedPath vaultPath = null!;
            if (vaultFS is FileStream fs) vaultPath = NormalizedPath.From(fs.Name);
            else vaultPath = NormalizedPath.From($"{Path.GetTempPath()}\\{Encoding.UTF8.GetString(RandomNumberGenerator.GetBytes(10))}.vlt");
            //Create session clears EncryptedFilesList so we copy and then restore the copy via reflection
            var encryptedFilesListCopy = session.ENCRYPTED_FILES.ToDictionary(item => item.Key, item => item.Value);
            session.CreateSession(vaultPath, reader, password ??= new byte[16], salt, iterations);
            typeof(VaultSession).GetProperty(nameof(VaultSession.ENCRYPTED_FILES))!.SetValue(session, encryptedFilesListCopy);

            return session;
        }

        internal static ReadOnlySpan<byte> CreateKey(byte[]? password = null, byte[]? salt = null, int iterations = 1000)
        {
            Span<byte> key = new byte[PasswordHelper.KeySize];
            PasswordHelper.DeriveKey(password ??= new byte[16], salt ??= new byte[32], iterations, key);
            return key;
        }

        /// <summary>
        /// Creates empty instance of VaultRegistry using reflection to bypass private constructor
        /// </summary>
        /// <param name="session"></param>
        /// <param name="encryptionOptionsService"></param>
        /// <returns>New instance of VaultRegistry</returns>
        internal static VaultRegistry CreateVaultRegistry(IVaultSession session)
        {
            var registryConstructor = typeof(VaultRegistry).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, new Type[] { typeof(IVaultSession) });
            return (VaultRegistry)registryConstructor!.Invoke(new object[] { session });
        }

        /// <summary>
        /// Creates vault file in temp folder with random name. Metadata is encrypted using AES-256-GCM with an empty 16 byte array as password<br/>
        /// Default vault file information:<br/>
        /// Version (1 byte) = 0<br/>
        /// Password (16 bytes) = Array of zeroes<br/>
        /// Salt (32 bytes) = Array of zeroes<br/>
        /// Iterations = 1000<br/>
        /// Encrypted metadata offsets[IV (12 bytes), Tag (16 bytes), File count (2 bytes), Metadata offsets (4096 bytes)]<br/>
        /// </summary>
        /// <returns>Path to the file</returns>
        internal static NormalizedPath CreateVaultFile(byte version = 0, byte[]? password = null, byte[]? salt = null, int iterations = 1000)
        {
            var path = NormalizedPath.From(Path.GetTempPath());
            var fileName = Path.GetRandomFileName();
            var provider = EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.Provider();

            //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number +  MetadataOffsetsSize (4KB (4096 bytes))]...
            int saltSize = 32;
            int metadataOffsetsSize = sizeof(ushort) + 4096;
            using FileStream fs = new FileStream($"{path}\\{fileName}.vlt", FileMode.CreateNew, FileAccess.Write);
            //Write vault header information
            fs.WriteByte(0);
            fs.Write(salt ??= new byte[saltSize]);
            byte[] iterationBytes = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32LittleEndian(iterationBytes, iterations);
            fs.Write(iterationBytes);
            ReadOnlySpan<byte> key = CreateKey(password, salt, iterations)[..provider.KeySize];
            //Write metadata
            SecureBuffer.SecureLargeBuffer encryptedEmptyMetadata = null!;
            try
            {
                encryptedEmptyMetadata = provider.EncryptionAlgorithm.EncryptBytes(new byte[metadataOffsetsSize], key);
                fs.Write(encryptedEmptyMetadata.AsSpan);
            }
            finally
            {
                if(encryptedEmptyMetadata is not null) encryptedEmptyMetadata.Dispose();
            }
            return NormalizedPath.From($"{path}\\{fileName}.vlt");
        }

        /// <summary>
        /// Creates vault file in temp folder with random name by calling <see cref="CreateVaultFile"/> and writes encrypted <paramref name="filesToEncrypt"/> to the vault.
        /// <br/>
        /// <paramref name="filesToEncrypt"/> are encrypted using random encryption with ID between 1 and 32
        /// <br/>
        /// Additionally updates <paramref name="vaultSessionWithReader"/> with information from new vault
        /// </summary>
        /// <param name="filesToEncrypt"></param>
        /// <param name="vaultSessionWithReader"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="iterations"></param>
        /// <returns>Tuple containing path to the file and array of <see cref="EncryptionOptions.FileEncryptionOptions"/></returns>
        internal static (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) CreateVaultFileWithEncryptedFileList(byte[][] filesToEncrypt, IVaultSession vaultSessionWithReader = null!, byte[]? password = null, byte[]? salt = null, int iterations = 1000)
        {
            password ??= new byte[16];
            salt ??= new byte[vaultSessionWithReader.VAULT_READER.SaltSize];
            ReadOnlySpan<byte> key = CreateKey(password, salt, iterations);
            vaultSessionWithReader ??= CreateFilledSessionInstanceWithReader(key, 0);
            var path = CreateVaultFile(0, password, salt);
            var fileEncryptionOptions = new EncryptionOptions.FileEncryptionOptions[filesToEncrypt.Length];
            var offsets = new long[filesToEncrypt.Length];
            var service = new EncryptionOptionsService(vaultSessionWithReader);


            using FileStream fs = new FileStream(path!, FileMode.Open, FileAccess.ReadWrite);
            SetVaultSessionFromStream(vaultSessionWithReader, fs, password);
            //Replace the mocked list with real one
            vaultSessionWithReader.ENCRYPTED_FILES.Clear();
            for (int i = 0; i < filesToEncrypt.Length; i++)
            {
                fs.Seek(0, SeekOrigin.End);

                //Add to encrypted files list
                SecureBuffer.SecureLargeBuffer fileNameBytes = new SecureBuffer.SecureLargeBuffer(100);
                RandomNumberGenerator.Fill(fileNameBytes.AsSpan);
                var algorithm = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[(byte)RandomNumberGenerator.GetInt32(32)];

                ulong fileSize = (ulong)(filesToEncrypt[i].Length + algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize);
                vaultSessionWithReader.ENCRYPTED_FILES.Add(fs.Position, new EncryptedFileInfo(Encoding.UTF8.GetString(fileNameBytes.AsSpan), fileSize, algorithm));

                //Write encryption options
                offsets[i] = fs.Position;
                fileEncryptionOptions[i] = new EncryptionOptions.FileEncryptionOptions(version: 0, fileNameBytes, fileSize, algorithm.ID, chunked: false, chunkInformation: null);
                SecureBuffer.SecureLargeBuffer encryptedFileEncryptionOptions = service.EncryptAndPadFileEncryptionOptions(fileEncryptionOptions[i]);
                fs.Write(encryptedFileEncryptionOptions.AsSpan);
                encryptedFileEncryptionOptions.Dispose();

                //Write the encrypted file
                SecureBuffer.SecureLargeBuffer encryptedFile = algorithm.Provider().EncryptionAlgorithm.EncryptBytes(filesToEncrypt[i], key[..algorithm.Provider().KeySize]);
                fs.Write(encryptedFile.AsSpan);
                encryptedFile.Dispose();
            }

            byte[] metadataOffsets = new byte[sizeof(ushort) + 4096];
            BinaryPrimitives.WriteUInt16LittleEndian(metadataOffsets.AsSpan(), (ushort)filesToEncrypt.Length);
            Span<byte> offsetBytes = stackalloc byte[8];
            for (int i = 0; i < filesToEncrypt.Length; i++)
            {
                BinaryPrimitives.WriteInt64LittleEndian(metadataOffsets.AsSpan(2 + (i * 8), 8), offsets[i]);
            }
            SecureBuffer.SecureLargeBuffer encryptedMetadataOffsets = vaultSessionWithReader.VAULT_READER.VaultEncryption(metadataOffsets);
            //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number +  MetadataOffsetsSize (4KB (4096 bytes))]...
            fs.Seek(1 + 32 + 4, SeekOrigin.Begin); //Seeking to where offsets are placed
            fs.Write(encryptedMetadataOffsets.AsSpan);
            encryptedMetadataOffsets.Dispose();

            return (path, fileEncryptionOptions);
        }

        /// <summary>
        /// Creates vault file in temp folder with random name by calling <see cref="CreateVaultFile"/>. Creates <paramref name="numberOfFiles"/> of randomly generated files to encrypt then calls <see cref="CreateVaultFileWithEncryptedFileList(byte[][], IVaultSession, byte[]?, byte[]?, int)"/>
        /// <br/>
        /// Each of randomly generated files is encrypted seperately using random encryption with ID between 1 and 32
        /// <br/>
        /// Additionally updates <paramref name="vaultSessionWithReader"/> with information from new vault
        /// </summary>
        /// <param name="numberOfFiles">Number of files to randomly generate to encrypt</param>
        /// <returns>Tuple containing path to the file and array of <see cref="EncryptionOptions.FileEncryptionOptions"/></returns>
        internal static (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) CreateVaultFileWithEncryptedFileList(byte numberOfFiles = 1, IVaultSession vaultSessionWithReader = null!, byte[]? password = null, byte[]? salt = null, int iterations = 1000)
        {
            byte[][] filesToEncrypt = new byte[numberOfFiles][];
            for (int i = 0; i < numberOfFiles; i++)
            {
                int fileSize = RandomNumberGenerator.GetInt32(1, 100);
                filesToEncrypt[i] = RandomNumberGenerator.GetBytes(fileSize);
            }
            return CreateVaultFileWithEncryptedFileList(filesToEncrypt, vaultSessionWithReader, password, salt, iterations);
        }

        /// <summary>
        /// Returns KVP pointing to encrypted file from the <see cref="IVaultSession.ENCRYPTED_FILES"/> at <paramref name="position"/>
        /// </summary>
        /// <param name="position">Zero based indexed position of KVP</param>
        /// <param name="vaultFS">Stream to vault</param>
        /// <param name="vaultSessionWithReader">Vault session with reader tied to <paramref name="vaultFS"/></param>
        /// <returns>KVP containing offset and information about encrypted file</returns>
        public static KeyValuePair<long, EncryptedFileInfo> GetOffsetKVPFromVaultAtPosition(int position, Stream vaultFS, IVaultSession vaultSessionWithReader)
        {
            long[] offsets = vaultSessionWithReader.VAULT_READER.ReadMetadataOffsets(vaultFS);
            long offsetToGet = offsets[position];
            EncryptionOptionsService service = new EncryptionOptionsService(vaultSessionWithReader);
            using (EncryptionOptions.FileEncryptionOptions fileEncryptionOptions = service.GetDecryptedFileEncryptionOptions(vaultFS, offsetToGet))
            {
                EncryptedFileInfo fileInfoToGet = new EncryptedFileInfo(Encoding.UTF8.GetString(fileEncryptionOptions.FileName.AsSpan), fileEncryptionOptions.FileSize, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[fileEncryptionOptions.EncryptionAlgorithm]);
                return new KeyValuePair<long, EncryptedFileInfo>(offsetToGet, fileInfoToGet);
            }
        }
    }
}
