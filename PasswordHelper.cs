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
        /// <summary>
        /// Generates 32 byte array with cryptographically strong random data 
        /// </summary>
        /// <returns></returns>
        internal static byte[] GenerateRandomSalt()
        {
            byte[] salt = new byte[32];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }


        internal static byte[] DeriveKey(string password)
        {
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, VaultSession.SALT, VaultSession.ITERATIONS, HashAlgorithmName.SHA512))
            {
                return pbkdf2.GetBytes(128);
            }
        }
    }


}
