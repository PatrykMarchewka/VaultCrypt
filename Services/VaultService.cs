using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Services
{
    public interface IVaultService
    {
        void CreateVault(NormalizedPath folderPath, string vaultName, byte[] password, int iterations);
    }

    public class VaultService : IVaultService
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
        public void CreateVault(NormalizedPath folderPath, string vaultName, byte[] password, int iterations)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(folderPath);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(vaultName);
            ArgumentNullException.ThrowIfNull(password);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);

            if (!Directory.Exists(folderPath)) Directory.CreateDirectory(folderPath!);
            NormalizedPath vaultPath = NormalizedPath.From($"{folderPath}\\{vaultName}.vlt")!;
            VaultReader reader = VaultRegistry.GetVaultReader(VaultSession.NewestVaultVersion);
            byte[] salt = null!;
            byte[] buffer = null!;
            byte[] encryptedMetadata = null!;
            byte[] data = null!;
            try
            {
                salt = PasswordHelper.GenerateRandomSalt(reader.SaltSize);
                buffer = reader.PrepareVaultHeader(salt, iterations);
                VaultSession.CreateSession(vaultPath, reader, password, salt, iterations);
                encryptedMetadata = reader.VaultEncryption(new byte[sizeof(ushort) + reader.MetadataOffsetsSize]);
                data = new byte[buffer.Length + encryptedMetadata.Length];
                Buffer.BlockCopy(buffer, 0, data, 0, buffer.Length);
                Buffer.BlockCopy(encryptedMetadata, 0, data, buffer.Length, encryptedMetadata.Length);
                File.WriteAllBytes(vaultPath!, data);
            }
            finally
            {
                if (salt is not null) CryptographicOperations.ZeroMemory(salt);
                if (buffer is not null) CryptographicOperations.ZeroMemory(buffer);
                if (encryptedMetadata is not null) CryptographicOperations.ZeroMemory(encryptedMetadata);
                if (data is not null) CryptographicOperations.ZeroMemory(data);
            }


        }
    }
}
