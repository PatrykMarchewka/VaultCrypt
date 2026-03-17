using Newtonsoft.Json.Linq;
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
        /// Created instance uses <see cref="FakeVaultReader"/> by default, you can pass your own reader or use <see cref="CreateFilledSessionInstanceWithReader(byte[]?, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?)"/> instead
        /// </summary>
        /// <param name="key"></param>
        /// <param name="vaultPath"></param>
        /// <param name="encryptedFiles"></param>
        /// <param name="vaultReader"></param>
        /// <returns>New instance of VaultSession with filled attributes</returns>
        internal static VaultSession CreateFilledSessionInstance(byte[] key, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null, IVaultReader? vaultReader = null)
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
            typeof(VaultSession).GetProperty(nameof(VaultSession.KEY))!.SetValue(session, key);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULTPATH))!.SetValue(session, vaultPath ?? vaultPathDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.ENCRYPTED_FILES))!.SetValue(session, encryptedFiles ?? encryptedFilesDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULT_READER))!.SetValue(session, vaultReader ?? readerDefault);

            return session;
        }

        /// <summary>
        /// Creates instance of VaultSession and fills it with provided values or predetermined default ones using reflection to bypass private constructor and field setters <br/>
        /// Created instance uses <see cref="FakeVaultReader"/> by default, you can pass your own reader or use <see cref="CreateFilledSessionInstanceWithReader(byte[]?, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?)"/> instead
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="iterations"></param>
        /// <param name="vaultPath"></param>
        /// <param name="encryptedFiles"></param>
        /// <param name="vaultReader"></param>
        /// <returns></returns>
        internal static VaultSession CreateFilledSessionInstance(byte[]? password = null, byte[]? salt = null, int iterations = 1000, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null, IVaultReader? vaultReader = null)
        {
            password ??= new byte[16];
            salt ??= new byte[32];
            byte[] key = PasswordHelper.DeriveKey(password, salt, iterations);
            return CreateFilledSessionInstance(key, vaultPath, encryptedFiles, vaultReader);
        }

        /// <summary>
        /// Calls internal <see cref="CreateFilledSessionInstance(byte[]?, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?, IVaultReader?)"/> and replaces fake reader with real one utilizing newest vault version
        /// </summary>
        /// <param name="key"></param>
        /// <param name="vaultPath"></param>
        /// <param name="encryptedFiles"></param>
        /// <returns>New instance of VaultSession with filled attributes</returns>
        internal static VaultSession CreateFilledSessionInstanceWithReader(byte[] key, byte version = VaultSession.NewestVaultVersion, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null)
        {
            var session = CreateFilledSessionInstance(key, vaultPath, encryptedFiles, null);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULT_READER))!.SetValue(session, CreateVaultRegistry(session).GetVaultReader(VaultSession.NewestVaultVersion));
            return session;
        }

        /// <summary>
        /// Calls internal <see cref="CreateFilledSessionInstance(byte[]?, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?, IVaultReader?)"/> and replaces fake reader with real one utilizing newest vault version
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
            byte[] key = PasswordHelper.DeriveKey(password, salt, iterations);
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
        /// For compatibility it defaults to same values as <see cref="CreateFilledSessionInstance(byte[]?, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?, IVaultReader?)"/>
        /// Default vault file information:<br/>
        /// Version (1 byte) = 0<br/>
        /// Salt (32 bytes) = Array of zeroes<br/>
        /// Iterations (4 bytes) = 1000 (Little endian)<br/>
        /// Encrypted metadata offsets[IV (12 bytes), Tag (16 bytes), File count (2 bytes), Metadata offsets (4096 bytes)]<br/>
        /// Password used to encrypt (16 bytes) = Array of zeroes
        /// </summary>
        /// <returns>Path to the file</returns>
        internal static NormalizedPath CreateVaultFile(byte version = 0, byte[]? password = null, byte[]? salt = null, int iterations = 1000)
        {
            var path = NormalizedPath.From(Path.GetTempPath());
            var fileName = Path.GetRandomFileName();
            var provider = EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.Provider();

            //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number +  MetadataOffsetsSize (4KB (4096 bytes))]...
            using FileStream fs = new FileStream($"{path}\\{fileName}.vlt", FileMode.CreateNew, FileAccess.Write);
            fs.WriteByte(0);
            fs.Write(salt ??= new byte[32]);
            byte[] iterationBytes = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(iterationBytes, iterations);
            fs.Write(iterationBytes);
            var key = PasswordHelper.DeriveKey(password ??= new byte[16], salt ??= new byte[32], 1000)[..provider.KeySize];
            byte[] encryptedEmptyMetadata = provider.EncryptionAlgorithm.EncryptBytes(new byte[sizeof(ushort) + 4096], key);
            fs.Write(encryptedEmptyMetadata);

            return NormalizedPath.From($"{path}\\{fileName}.vlt");
        }

        /// <summary>
        /// Creates vault file in temp folder with random name by calling <see cref="CreateVaultFile"/>. Adds <paramref name="numberOfFiles"/> of randomly generated file encryption options inside.
        /// <br/>
        /// Simulates encrypted files by writing random bytes right after the encryption options
        /// </summary>
        /// <param name="numberOfFiles"></param>
        /// <returns>Tuple containing path to the file and array of <see cref="EncryptionOptions.FileEncryptionOptions"/></returns>
        internal static (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) CreateVaultFileWithEncryptedFileList(IVaultSession vaultSessionWithReader = null!, byte numberOfFiles = 1, byte[]? password = null, byte[]? salt = null, int iterations = 1000)
        {
            password ??= new byte[16];
            salt ??= new byte[vaultSessionWithReader.VAULT_READER.SaltSize];
            var key = PasswordHelper.DeriveKey(password, salt, iterations);
            vaultSessionWithReader ??= CreateFilledSessionInstanceWithReader(key, 0);
            var path = CreateVaultFile(0, password, salt);
            var fileEncryptionOptions = new EncryptionOptions.FileEncryptionOptions[numberOfFiles];
            var offsets = new long[numberOfFiles];
            var service = new EncryptionOptionsService(vaultSessionWithReader);
            var provider = EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.Provider();


            using FileStream fs = new FileStream(path!, FileMode.Open, FileAccess.ReadWrite);
            SetVaultSessionFromStream(vaultSessionWithReader, fs, password);
            //Replace the mocked list with real one
            vaultSessionWithReader.ENCRYPTED_FILES.Clear();
            for (int i = 0; i < numberOfFiles; i++)
            {
                fs.Seek(0, SeekOrigin.End);

                //Add to encrypted files list
                byte[] fileNameBytes = RandomNumberGenerator.GetBytes(100);
                ulong fileSize = (ulong)RandomNumberGenerator.GetInt32(100);
                byte algorithmID = (byte)RandomNumberGenerator.GetInt32(32);
                vaultSessionWithReader.ENCRYPTED_FILES.Add(fs.Position, new EncryptedFileInfo(Encoding.UTF8.GetString(fileNameBytes), fileSize, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[algorithmID]));

                //Write encryption options
                offsets[i] = fs.Position;
                fileEncryptionOptions[i] = new EncryptionOptions.FileEncryptionOptions(version: 0, fileNameBytes, fileSize, algorithmID, chunked: false, chunkInformation: null);
                byte[] encrypted = service.EncryptAndPadFileEncryptionOptions(fileEncryptionOptions[i]);
                fs.Write(encrypted);

                //Write the 'encrypted' file
                fs.Write(RandomNumberGenerator.GetBytes((int)fileSize));
            }

            byte[] metadataOffsets = new byte[sizeof(ushort) + 4096];
            BinaryPrimitives.WriteUInt16LittleEndian(metadataOffsets.AsSpan(), numberOfFiles);
            Span<byte> offsetBytes = stackalloc byte[8];
            for (int i = 0; i < numberOfFiles; i++)
            {
                BinaryPrimitives.WriteInt64LittleEndian(metadataOffsets.AsSpan(2 + (i * 8), 8), offsets[i]);
            }
            byte[] encryptedMetadataOffsets = provider.EncryptionAlgorithm.EncryptBytes(metadataOffsets, key[..provider.KeySize]);
            //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number +  MetadataOffsetsSize (4KB (4096 bytes))]...
            fs.Seek(1 + 32 + 4, SeekOrigin.Begin); //Seeking to where offsets are placed
            fs.Write(encryptedMetadataOffsets);

            return (path, fileEncryptionOptions);
        }
    }
}
