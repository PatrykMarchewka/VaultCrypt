using Newtonsoft.Json.Linq;
using System;
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
        internal static string CreateTemporaryFile(int size)
        {
            var path = Path.GetTempFileName();
            File.WriteAllBytes(path, RandomNumberGenerator.GetBytes(size));
            return path;
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
        /// Created instance uses <see cref="FakeVaultReader"/>, if you require real reader call internal <see cref="CreateFilledSessionInstanceWithReader(byte[]?, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?)"/> instead
        /// </summary>
        /// <param name="key"></param>
        /// <param name="vaultPath"></param>
        /// <param name="encryptedFiles"></param>
        /// <param name="vaultReader"></param>
        /// <returns>New instance of VaultSession with filled attributes</returns>
        internal static VaultSession CreateFilledSessionInstance(byte[]? key = null, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null, IVaultReader? vaultReader = null)
        {
            byte[] keyDefault = new byte[128] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127 };

            NormalizedPath vaultPathDefault = NormalizedPath.From("C:\\FilledSessionInstance\\");
            Dictionary<long, EncryptedFileInfo> encryptedFilesDefault = new()
            {
                {0, new EncryptedFileInfo(null, 0, null) },
                {1, new EncryptedFileInfo("secret.pdf", 1_234, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0]) },
                {10, new EncryptedFileInfo("anotherone.mp3", 12_345, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[1]) }
            };
            IVaultReader readerDefault = new FakeVaultReader();

            var session = (VaultSession)Activator.CreateInstance(typeof(VaultSession), nonPublic: true)!;
            typeof(VaultSession).GetProperty(nameof(VaultSession.KEY))!.SetValue(session, key ?? keyDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULTPATH))!.SetValue(session, vaultPath ?? vaultPathDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.ENCRYPTED_FILES))!.SetValue(session, encryptedFiles ?? encryptedFilesDefault);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULT_READER))!.SetValue(session, vaultReader ?? readerDefault);

            return session;
        }

        /// <summary>
        /// Calls internal <see cref="CreateFilledSessionInstance(byte[]?, NormalizedPath?, Dictionary{long, EncryptedFileInfo}?, IVaultReader?)"/> and replaces fake reader with real one
        /// </summary>
        /// <param name="key"></param>
        /// <param name="vaultPath"></param>
        /// <param name="encryptedFiles"></param>
        /// <returns>New instance of VaultSession with filled attributes</returns>
        internal static VaultSession CreateFilledSessionInstanceWithReader(byte[]? key = null, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null)
        {
            var session = CreateFilledSessionInstance(key, vaultPath, encryptedFiles, null);
            var optionsService = new EncryptionOptionsService(session);
            typeof(VaultSession).GetProperty(nameof(VaultSession.VAULT_READER))!.SetValue(session, CreateVaultRegistry(session, optionsService).GetVaultReader(VaultSession.NewestVaultVersion));
            return session;
        }

        /// <summary>
        /// Creates empty instance of VaultRegistry using reflection to bypass private constructor
        /// </summary>
        /// <param name="session"></param>
        /// <param name="encryptionOptionsService"></param>
        /// <returns>New instance of VaultRegistry</returns>
        internal static VaultRegistry CreateVaultRegistry(IVaultSession session, IEncryptionOptionsService encryptionOptionsService)
        {
            var registryConstructor = typeof(VaultRegistry).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, new Type[] { typeof(IVaultSession), typeof(IEncryptionOptionsService) });
            return (VaultRegistry)registryConstructor!.Invoke(new object[] { session, encryptionOptionsService });
        }
    }
}
