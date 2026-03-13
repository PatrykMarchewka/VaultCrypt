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
    }
}
