using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class PasswordHelper
    {
        internal static byte[] GenerateRandomSalt(byte size = 32)
        {
            byte[] salt = new byte[size];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }


        internal static byte[] DeriveKey(string password, Encryption.VaultEncryptionOptions encryptionOptions)
        {
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, encryptionOptions.salt, (int)encryptionOptions.iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32);
            }
        }
    }


    internal class VaultKeySession : IDisposable
    {
        internal readonly byte[] KEY;

        internal VaultKeySession(string password, Encryption.VaultEncryptionOptions encryptionOptions)
        {
            this.KEY = PasswordHelper.DeriveKey(password, encryptionOptions);
        }


        public void Dispose()
        {
            Array.Clear(KEY, 0, KEY.Length);
        }
    }
}
