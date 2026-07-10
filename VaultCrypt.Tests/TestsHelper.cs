using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    /// <summary>
    /// Class designated to hold helper methods for testing.
    /// Helper methods are intended to work WITHOUT relying on external sources such as services on purpose
    /// </summary>
    internal class TestsHelper
    {
        internal record VaultInformation(NormalizedPath Path, byte Version, byte[] Password, byte[] Salt, int Iterations, Dictionary<long, EncryptedFileInfo> EncryptedFiles) {
            public VaultSession VaultSession = TestsHelper.CreateFilledSessionInstance(Version, Password, Salt, Iterations, Path, EncryptedFiles);
        }

        internal static VaultSession EmptySession = (VaultSession)Activator.CreateInstance(typeof(VaultSession), nonPublic: true)!;

        /// <summary>
        /// Password used to unlock vaults created for tests
        /// </summary>
        internal static readonly byte[] TestDataVaultPassword = new byte[] { 82, 0, 111, 0, 117, 0, 110, 0, 100, 0, 84, 0, 114, 0, 105, 0, 112, 0, 84, 0, 101, 0, 115, 0, 116, 0, 115, 0 }; //Translates to "RoundTripTests", used as password for TestData vaults
        internal const int TestDataVaultPasswordIterations = 1_000_000;

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
        internal static readonly VaultInformation EmptyVaultV0Information = new VaultInformation(Path: NormalizedPath.From($"{GetTestDataDirectory}\\TestData\\EmptyVault_v0.vlt"), Version: 0, Password: TestDataVaultPassword, Salt: new byte[] { 195, 219, 86, 3, 88, 131, 238, 159, 16, 13, 104, 192, 166, 92, 241, 4, 4, 10, 62, 210, 252, 198, 41, 106, 144, 238, 190, 163, 117, 175, 29, 224 }, Iterations: TestDataVaultPasswordIterations, EncryptedFiles: new Dictionary<long, EncryptedFileInfo>());

        /// <summary>
        /// Information about vault with lorem ipsum and pattern files in it. Vault created using release v1.3.0
        /// </summary>
        internal static readonly VaultInformation FilledVaultV0Information = new VaultInformation(Path: NormalizedPath.From($"{GetTestDataDirectory}\\TestData\\FilledVault_v0.vlt"), Version: 0, Password: TestDataVaultPassword, Salt: new byte[] { 225, 243, 62, 251, 189, 149, 16, 122, 174, 149, 207, 59, 165, 47, 181, 136, 37, 180, 52, 129, 35, 9, 195, 231, 142, 42, 45, 47, 212, 165, 253, 45 }, Iterations: TestDataVaultPasswordIterations, EncryptedFiles: new Dictionary<long, EncryptedFileInfo>() { { 4163, new EncryptedFileInfo("LoremIpsum.txt", 99821, EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM) }, { 105008, new EncryptedFileInfo("PatternFile.txt", 18000504, EncryptionAlgorithm.EncryptionAlgorithmInfo.ChaCha20Poly1305) } });


        /// <summary>
        /// Lorem ipsum text file
        /// </summary>
        internal static readonly NormalizedPath LoremIpsumFilePath = NormalizedPath.From($"{GetTestDataDirectory}\\TestData\\LoremIpsum.txt");

        /// <summary>
        /// 17MB text file with repeating pattern data
        /// </summary>
        internal static readonly NormalizedPath PatternFilePath = NormalizedPath.From($"{GetTestDataDirectory}\\TestData\\PatternFile.txt");

        /// <summary>
        /// Tests data holding function copying vault file that returns location of the copied file and information about the vault <br/>
        /// WARNING: VaultInformation.Path will point to the original file location while VaultInformation.VaultSession.VAULTPATH points to the copy location
        /// </summary>
        public static TheoryData<Func<NormalizedPath>, VaultInformation> VaultFileCombinations = new TheoryData<Func<NormalizedPath>, VaultInformation>()
        {
            {CopyEmptyVaultV0, EmptyVaultV0Information },
            {CopyFilledVaultV0, FilledVaultV0Information }
        };

        /// <summary>
        /// Filters <see cref="VaultFileCombinations"/> to show only vaults that have no encrypted files in them
        /// </summary>
        public static TheoryData<Func<NormalizedPath>, VaultInformation> EmptyVaultFileCombinations
        {
            get
            {
                var data = new TheoryData<Func<NormalizedPath>, VaultInformation>();
                foreach (var item in VaultFileCombinations)
                {
                    Func<NormalizedPath> copyFunction = (Func<NormalizedPath>)item[0];
                    VaultInformation information = (VaultInformation)item[1];

                    if (information.VaultSession.ENCRYPTED_FILES.Count == 0) data.Add(copyFunction, information);
                }

                return data;
            }
        }

        /// <summary>
        /// Filters <see cref="VaultFileCombinations"/> to show only vaults that have atleast 1 encrypted item in them
        /// </summary>
        public static TheoryData<Func<NormalizedPath>, VaultInformation> FilledVaultFileCombinations
        {
            get
            {
                var data = new TheoryData<Func<NormalizedPath>, VaultInformation>();
                foreach (var item in VaultFileCombinations)
                {
                    Func<NormalizedPath> copyFunction = (Func<NormalizedPath>)item[0];
                    VaultInformation information = (VaultInformation)item[1];

                    if (information.VaultSession.ENCRYPTED_FILES.Count > 1) data.Add(copyFunction, information);
                }

                return data;
            }
        }

        /// <summary>
        /// Tests data holding invalid values for <see cref="NormalizedPath"/> and exception they should throw when passed as arguments
        /// </summary>
        public static TheoryData<NormalizedPath?, Type> InvalidPaths = new TheoryData<NormalizedPath?, Type>()
        {
            {null, typeof(ArgumentNullException)},
            {NormalizedPath.From("  "), typeof(ArgumentException)},
            {NormalizedPath.From(string.Empty), typeof(ArgumentException)}
        };

        public static TheoryData<string?, Type> InvalidStrings = new TheoryData<string?, Type>()
        {
            {null, typeof(ArgumentNullException)},
            {"  ", typeof(ArgumentException)},
            {string.Empty, typeof(ArgumentException)}
        };

        /// <summary>
        /// Tests data holding all Encryption algorithms
        /// </summary>
        public static TheoryData<EncryptionAlgorithm.EncryptionAlgorithmInfo> EncryptionAlgorithms
        {
            get
            {
                var data = new TheoryData<EncryptionAlgorithm.EncryptionAlgorithmInfo>();

                foreach (var item in EncryptionAlgorithm.GetEncryptionAlgorithmInfo.Values)
                {
                    data.Add(item);
                }

                return data;
            }
        }

        /// <summary>
        /// Returns Cartesian product of <see cref="EncryptionAlgorithms"/> and <see cref="VaultFileCombinations"/> (A × B)
        /// </summary>
        public static TheoryData<EncryptionAlgorithm.EncryptionAlgorithmInfo, Func<NormalizedPath>, VaultInformation> EncryptionAlgorithmsAndVaultFileCombinationsCartesian
        {
            get
            {
                var data = new TheoryData<EncryptionAlgorithm.EncryptionAlgorithmInfo, Func<NormalizedPath>, VaultInformation>();
                foreach (var algorithmObject in EncryptionAlgorithms)
                {
                    foreach (var vaultFile in VaultFileCombinations)
                    {
                        var algorithm = (EncryptionAlgorithm.EncryptionAlgorithmInfo)algorithmObject[0];
                        var method = (Func<NormalizedPath>)vaultFile[0];
                        var information = (VaultInformation)vaultFile[1];

                        data.Add(algorithm, method, information);
                    }
                }
                return data;
            }

        }

        /// <summary>
        /// Returns newest VaultReader version
        /// </summary>
        internal static IVaultReader GetNewestReader => new VaultV0Reader();

        /// <summary>
        /// Empty secure buffer with length of zero
        /// </summary>
        public static ISecureBuffer EmptySecureBuffer = SecureBuffer.Create(0);

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
                nameBytes[i] = (byte)Random.Shared.Next(97, 123); //ASCII codes a-z
            }

            return Encoding.UTF8.GetString(nameBytes);
        }

        /// <summary>
        /// Creates instance of VaultSession and fills it with provided values or predetermined default ones using reflection to bypass private constructor and field setters
        /// </summary>
        /// <param name="version">Version of the vault</param>
        /// <param name="key">Key to open vault, required</param>
        /// <param name="vaultPath">Path to the vault, defaults to "C:\FilledSessionInstance\"</param>
        /// <param name="encryptedFiles">Encrypted files in the vault, defaults to 3 files, first corrupted at 0 offset, second called secret.pdf at 1_234 offset and last one called anotherone.mp3 at 12_345 offset</param>
        /// <returns>VaultSession filled with provided data</returns>
        internal static VaultSession CreateFilledSessionInstance(byte version, ReadOnlySpan<byte> key, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null)
        {
            NormalizedPath vaultPathDefault = NormalizedPath.From("C:\\FilledSessionInstance\\");
            Dictionary<long, EncryptedFileInfo> encryptedFilesDefault = new()
            {
                {0, new EncryptedFileInfo(null, 0, null) },
                {1, new EncryptedFileInfo("secret.pdf", 1_234, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0]) },
                {10, new EncryptedFileInfo("anotherone.mp3", 12_345, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[1]) }
            };

            var session = (VaultSession)Activator.CreateInstance(typeof(VaultSession), nonPublic: true)!;
            ISecureBuffer keyBuffer = SecureBuffer.Create(PasswordHelper.KeySize);
            key.CopyTo(keyBuffer.AsSpan);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VERSION))!.SetValue(session, version);
            typeof(VaultSession).GetProperty(nameof(VaultSession.KEY))!.SetValue(session, keyBuffer);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULTPATH))!.SetValue(session, vaultPath ?? vaultPathDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.ENCRYPTED_FILES))!.SetValue(session, encryptedFiles ?? encryptedFilesDefault);

            return session;
        }

        /// <inheritdoc cref="CreateFilledSessionInstance(ReadOnlySpan{byte}, byte, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?)"/>
        /// <param name="password">Password used to open vault, defaults to empty 16 byte array</param>
        /// <param name="salt">Salt used on password, defaults to empty 32 byte array</param>
        /// <param name="iterations">Number of iterations when deriving key, defaults to 1000</param>
        internal static VaultSession CreateFilledSessionInstance(byte version = 0, byte[]? password = null, byte[]? salt = null, int iterations = 1000, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null)
        {
            password ??= new byte[16];
            salt ??= new byte[32];
            ReadOnlySpan<byte> key = CreateKey(password, salt, iterations);
            return CreateFilledSessionInstance(version, key, vaultPath, encryptedFiles);
        }

        /// <summary>
        /// Uses reflection to change <see cref="IVaultSession.VAULTPATH"/>
        /// </summary>
        /// <param name="session">Session to change path of</param>
        /// <param name="newPath">New path to change it into</param>
        /// <returns><paramref name="session"/> after changing <see cref="IVaultSession.VAULTPATH"/></returns>
        internal static IVaultSession ChangeSessionVaultPath(IVaultSession session, NormalizedPath newPath)
        {
            session.GetType().GetProperty(nameof(IVaultSession.VAULTPATH))!.SetValue(session, newPath);
            return session;
        }

        private static NormalizedPath Copy(string sourceFilePath)
        {
            string directory = Path.GetTempPath();
            string sourceFileName = new FileInfo(sourceFilePath).Name;
            int errorCount = 0;
            while (errorCount < 10)
            {
                //Prefixing random number before file name to prevent throwing if multiple tests method want to copy at the same time, ensuring each test has its own copy of the file, collisions can still happen but the chance of them is very low
                NormalizedPath fullNewPath = NormalizedPath.From($"{directory}\\{Random.Shared.Next()}_{sourceFileName}");
                if (File.Exists(fullNewPath))
                {
                    //Collision happened, try to reroll the name
                    errorCount++;
                    continue;
                }

                try
                {
                    using var source = new FileStream(sourceFilePath, FileMode.Open, FileAccess.Read);
                    using var destination = new FileStream(fullNewPath, FileMode.CreateNew, FileAccess.Write);

                    source.CopyTo(destination);
                    return fullNewPath;
                }
                catch (IOException)
                {
                    //File could not be copied, try again
                    errorCount++;
                }
            }
            throw new System.Diagnostics.UnreachableException();
        }

        /// <summary>
        /// Copies empty v0 vault to a temp location
        /// </summary>
        /// <returns>Location to the copy</returns>
        internal static NormalizedPath CopyEmptyVaultV0()
        {
            var path = Copy(EmptyVaultV0Information.Path);
            ChangeSessionVaultPath(EmptyVaultV0Information.VaultSession, path);
            return path;
        }

        /// <summary>
        /// Copies filled v0 vault to a temp location
        /// </summary>
        /// <returns>Location to the copy</returns>
        internal static NormalizedPath CopyFilledVaultV0()
        {
            var path = Copy(FilledVaultV0Information.Path);
            ChangeSessionVaultPath(FilledVaultV0Information.VaultSession, path);
            return path;
        }

        /// <summary>
        /// Creates a new key using provided values or default ones
        /// </summary>
        /// <param name="password">Password to use, defaults to zeroed array of 16 bytes</param>
        /// <param name="salt">Salt to use, defaults to zeroed array of 32 bytes</param>
        /// <param name="iterations">Number of iterations to use, defaults to 1000</param>
        /// <returns>Key created from the provided values</returns>
        internal static ReadOnlySpan<byte> CreateKey(byte[]? password = null, byte[]? salt = null, int iterations = 1000)
        {
            Span<byte> key = new byte[PasswordHelper.KeySize];
            PasswordHelper.DeriveKey(password ??= new byte[16], salt ??= new byte[32], iterations, key);
            return key;
        }
    }
}
