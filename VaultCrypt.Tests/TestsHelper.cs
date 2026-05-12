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
        public record VaultInformation(NormalizedPath Path, byte Version, byte[] Password, byte[] Salt, int Iterations, Dictionary<long, EncryptedFileInfo> EncryptedFiles) {
            public IVaultSession VaultSession = TestsHelper.CreateFilledSessionInstance(Password, Salt, Iterations, Version, Path, EncryptedFiles);
        }

        public static VaultSession EmptySession = (VaultSession)Activator.CreateInstance(typeof(VaultSession), nonPublic: true)!;

        public static readonly byte[] TestDataVaultPassword = new byte[] { 82, 0, 111, 0, 117, 0, 110, 0, 100, 0, 84, 0, 114, 0, 105, 0, 112, 0, 84, 0, 101, 0, 115, 0, 116, 0, 115, 0 }; //Translates to "RoundTripTests", used as password for TestData vaults
        public const int TestDataVaultPasswordIterations = 1_000_000;

        private static string GetTestDataDirectory
        {
            get
            {
                var appDirectory = AppContext.BaseDirectory;

                while (!Directory.Exists(Path.Combine(appDirectory, "TestData")))
                {
                    appDirectory = Directory.GetParent(appDirectory)!.FullName;
                }

                return appDirectory;
            }
        }
        /// <summary>
        /// Information about empty vault with no files with it. Vault created using release v1.3.0
        /// </summary>
        public static VaultInformation EmptyVaultV0Information = new VaultInformation(Path: NormalizedPath.From($"{GetTestDataDirectory}\\TestData\\EmptyVault_v0.vlt"), Version: 0, Password: TestDataVaultPassword, Salt: new byte[] { 195, 219, 86, 3, 88, 131, 238, 159, 16, 13, 104, 192, 166, 92, 241, 4, 4, 10, 62, 210, 252, 198, 41, 106, 144, 238, 190, 163, 117, 175, 29, 224 }, Iterations: TestDataVaultPasswordIterations, EncryptedFiles: new Dictionary<long, EncryptedFileInfo>());

        /// <summary>
        /// Information about vault with lorem ipsum and pattern files in it. Vault created using release v1.3.0
        /// </summary>
        public static VaultInformation FilledVaultV0Information = new VaultInformation(Path: NormalizedPath.From($"{GetTestDataDirectory}\\TestData\\FilledVault_v0.vlt"), Version: 0, Password: TestDataVaultPassword, Salt: new byte[] { 225, 243, 62, 251, 189, 149, 16, 122, 174, 149, 207, 59, 165, 47, 181, 136, 37, 180, 52, 129, 35, 9, 195, 231, 142, 42, 45, 47, 212, 165, 253, 45 }, Iterations: TestDataVaultPasswordIterations, EncryptedFiles: new Dictionary<long, EncryptedFileInfo>() { { 4163, new EncryptedFileInfo("LoremIpsum.txt", 99821, EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM) }, { 105008, new EncryptedFileInfo("PatternFile.txt", 18000504, EncryptionAlgorithm.EncryptionAlgorithmInfo.ChaCha20Poly1305) } });


        /// <summary>
        /// Lorem ipsum text file
        /// </summary>
        public static NormalizedPath LoremIpsumFilePath => NormalizedPath.From($"{GetTestDataDirectory}\\TestData\\LoremIpsum.txt");

        /// <summary>
        /// 17MB text file with repeating pattern data
        /// </summary>
        public static NormalizedPath PatternFilePath => NormalizedPath.From($"{GetTestDataDirectory}\\TestData\\PatternFile.txt");

        /// <summary>
        /// Object holding Func<> to copy vault, session assosciated with it and VaultInformation about it
        /// </summary>
        public static IEnumerable<object[]> VaultFileCombinations => new List<object[]>
        {
            new object[]{(Func<NormalizedPath>)(() => CopyEmptyVaultV0()), EmptyVaultV0Information },
            new object[]{(Func<NormalizedPath>)(() => CopyFilledVaultV0()), FilledVaultV0Information },
        };

        /// <summary>
        /// Object holding invalid <see cref="NormalizedPath"/> values and <see cref="Type"/> of expected exception method should throw when trying to work with it
        /// </summary>
        public static IEnumerable<object?[]> InvalidPath =>
        [
            new object?[]{null, typeof(ArgumentNullException)},
            new object[]{NormalizedPath.From("  "), typeof(ArgumentException)},
            new object[]{NormalizedPath.From(string.Empty), typeof(ArgumentException)}
        ];


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
        /// Returns string of randomly generated a-z characters with length equal to <paramref name="nameLength"/>
        /// </summary>
        /// <param name="nameLength">Length of the desired text</param>
        /// <returns>Randomly generated string encoded in UTF8</returns>
        internal static string CreateRandomFileName(int nameLength = 10)
        {
            byte[] nameBytes = new byte[nameLength];
            for (int i = 0; i < nameLength; i++)
            {
                nameBytes[i] = (byte)RandomNumberGenerator.GetInt32(97, 123); //ASCII codes a-z
            }

            return Encoding.UTF8.GetString(nameBytes);
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
        /// Creates instance of VaultSession and fills it with provided values or predetermined default ones using reflection to bypass private constructor and field setters
        /// </summary>
        /// <param name="key">Key to open vault, required</param>
        /// <param name="version">Version of the vault, defaults to <see cref="VaultSession.NewestVaultVersion"/></param>
        /// <param name="vaultPath">Path to the vault, defaults to "C:\FilledSessionInstance\"</param>
        /// <param name="encryptedFiles">Encrypted files in the vault, defaults to 3 files, first corrupted at 0 offset, second called secret.pdf at 1_234 offset and last one called anotherone.mp3 at 12_345 offset</param>
        /// <returns>VaultSession filled with provided data</returns>
        internal static VaultSession CreateFilledSessionInstance(ReadOnlySpan<byte> key, byte version = VaultSession.NewestVaultVersion, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null)
        {
            NormalizedPath vaultPathDefault = NormalizedPath.From("C:\\FilledSessionInstance\\");
            Dictionary<long, EncryptedFileInfo> encryptedFilesDefault = new()
            {
                {0, new EncryptedFileInfo(null, 0, null) },
                {1, new EncryptedFileInfo("secret.pdf", 1_234, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0]) },
                {10, new EncryptedFileInfo("anotherone.mp3", 12_345, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[1]) }
            };

            var session = (VaultSession)Activator.CreateInstance(typeof(VaultSession), nonPublic: true)!;
            SecureBuffer.SecureKeyBuffer keyBuffer = new SecureBuffer.SecureKeyBuffer(PasswordHelper.KeySize);
            key.CopyTo(keyBuffer.AsSpan);
            typeof(VaultSession).GetProperty(nameof(VaultSession.KEY))!.SetValue(session, keyBuffer);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULTPATH))!.SetValue(session, vaultPath ?? vaultPathDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.ENCRYPTED_FILES))!.SetValue(session, encryptedFiles ?? encryptedFilesDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULT_READER))!.SetValue(session, CreateVaultRegistry(session).GetVaultReader(version));

            return session;
        }

        /// <inheritdoc cref="CreateFilledSessionInstance(ReadOnlySpan{byte}, byte, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?)"/>
        /// <param name="password">Password used to open vault, defaults to empty 16 byte array</param>
        /// <param name="salt">Salt used on password, defaults to empty 32 byte array</param>
        /// <param name="iterations">Number of iterations when deriving key, defaults to 1000</param>
        internal static VaultSession CreateFilledSessionInstance(byte[]? password = null, byte[]? salt = null, int iterations = 1000, byte version = VaultSession.NewestVaultVersion, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null)
        {
            password ??= new byte[16];
            salt ??= new byte[32];
            ReadOnlySpan<byte> key = CreateKey(password, salt, iterations);
            return CreateFilledSessionInstance(key, version, vaultPath, encryptedFiles);
        }

        internal static IVaultSession ChangeSessionVaultPath(IVaultSession session, NormalizedPath newPath)
        {
            session.GetType().GetProperty(nameof(IVaultSession.VAULTPATH))!.SetValue(session, newPath);
            return session;
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
            byte[] iterationBytes = new byte[sizeof(int)];
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

        private static NormalizedPath Copy(string fileName)
        {
            string directory = Path.GetTempPath();
            //Prefixing random number before file name to prevent throwing if multiple tests method want to copy at the same time, ensuring each test has its own copy of the file, collisions can still happen but the chance of them is very low
            NormalizedPath fullNewPath = NormalizedPath.From($"{directory}\\{Random.Shared.Next()}_{new FileInfo(fileName).Name}");
            File.Copy(fileName, fullNewPath);
            return fullNewPath;
        }

        public static NormalizedPath CopyEmptyVaultV0()
        {
            var path = Copy(EmptyVaultV0Information.Path);
            ChangeSessionVaultPath(EmptyVaultV0Information.VaultSession, path);
            return path;
        }

        public static NormalizedPath CopyFilledVaultV0()
        {
            var path = Copy(FilledVaultV0Information.Path);
            ChangeSessionVaultPath(FilledVaultV0Information.VaultSession, path);
            return path;
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


            string newVaultPath = $"{path}\\{fileName}.vlt";
            using FileStream fs = new FileStream(newVaultPath, FileMode.CreateNew, FileAccess.Write);
            try
            {
                //Write vault header information
                fs.WriteByte(0);
                fs.Write(salt ??= new byte[saltSize]);
                byte[] iterationBytes = new byte[sizeof(int)];
                BinaryPrimitives.WriteInt32LittleEndian(iterationBytes, iterations);
                fs.Write(iterationBytes);
                ReadOnlySpan<byte> key = CreateKey(password, salt, iterations)[..provider.KeySize];
                //Write metadata
                using (SecureBuffer.SecureLargeBuffer encryptedEmptyMetadata = provider.EncryptionAlgorithm.EncryptBytes(new byte[metadataOffsetsSize], key))
                {
                    fs.Write(encryptedEmptyMetadata.AsSpan);
                }
                return NormalizedPath.From(newVaultPath);
            }
            catch (Exception)
            {
                //Failed to create vault, delete entire file
                File.Delete(newVaultPath);
                throw;
            }
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
            var fileEncryptionOptions = new EncryptionOptions.FileEncryptionOptions[filesToEncrypt.Length];
            var offsets = new long[filesToEncrypt.Length];
            var service = new EncryptionOptionsService(vaultSessionWithReader);

            var path = CreateVaultFile(0, password, salt);
            try
            {
                using FileStream fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite);
                SetVaultSessionFromStream(vaultSessionWithReader, fs, password);
                //Replace the mocked list with real one
                vaultSessionWithReader.ENCRYPTED_FILES.Clear();
                for (int i = 0; i < filesToEncrypt.Length; i++)
                {
                    fs.Seek(0, SeekOrigin.End);

                    //Add to encrypted files list
                    SecureBuffer.SecureLargeBuffer fileNameBytes = new SecureBuffer.SecureLargeBuffer(100);
                    try
                    {
                        RandomNumberGenerator.Fill(fileNameBytes.AsSpan);
                        var algorithm = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[(byte)RandomNumberGenerator.GetInt32(32)];

                        ulong fileSize = (ulong)(filesToEncrypt[i].Length + algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize);
                        vaultSessionWithReader.ENCRYPTED_FILES.Add(fs.Position, new EncryptedFileInfo(Encoding.UTF8.GetString(fileNameBytes.AsSpan), fileSize, algorithm));

                        //Write encryption options
                        offsets[i] = fs.Position;
                        fileEncryptionOptions[i] = new EncryptionOptions.FileEncryptionOptions(version: 0, fileNameBytes, fileSize, algorithm.ID, chunked: false, chunkInformation: null);
                        using (SecureBuffer.SecureLargeBuffer encryptedFileEncryptionOptions = service.PadAndEncryptFileEncryptionOptions(fileEncryptionOptions[i]))
                        {
                            fs.Write(encryptedFileEncryptionOptions.AsSpan);
                        }

                        using (SecureBuffer.SecureLargeBuffer encryptedFile = algorithm.Provider().EncryptionAlgorithm.EncryptBytes(filesToEncrypt[i], key[..algorithm.Provider().KeySize]))
                        {
                            fs.Write(encryptedFile.AsSpan);
                        }
                    }
                    catch (Exception)
                    {
                        fileNameBytes.Dispose();
                        throw;
                    }
                }

                byte[] metadataOffsets = new byte[sizeof(ushort) + 4096];
                BinaryPrimitives.WriteUInt16LittleEndian(metadataOffsets.AsSpan(), (ushort)filesToEncrypt.Length);
                for (int i = 0; i < filesToEncrypt.Length; i++)
                {
                    BinaryPrimitives.WriteInt64LittleEndian(metadataOffsets.AsSpan(2 + (i * 8), 8), offsets[i]);
                }

                using (SecureBuffer.SecureLargeBuffer encryptedMetadataOffsets = vaultSessionWithReader.VAULT_READER.VaultEncryption(metadataOffsets))
                {
                    //v0 = [version (1byte)][salt (32 bytes)][iterations (4 bytes)] + [metadata offsets (28 bytes for AES decryption + 2 bytes ushort number +  MetadataOffsetsSize (4KB (4096 bytes))]...
                    fs.Seek(1 + 32 + 4, SeekOrigin.Begin); //Seeking to where offsets are placed
                    fs.Write(encryptedMetadataOffsets.AsSpan);
                }

                return (path, fileEncryptionOptions);
            }
            catch (Exception)
            {
                File.Delete(path);
                throw;
            }
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
                EncryptedFileInfo fileInfoToGet = new EncryptedFileInfo(fileEncryptionOptions.GetFileName(), fileEncryptionOptions.FileSize, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[fileEncryptionOptions.EncryptionAlgorithm]);
                return new KeyValuePair<long, EncryptedFileInfo>(offsetToGet, fileInfoToGet);
            }
        }
    }
}
