using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    public class PasswordHelper
    {
        public const int KeySize = 128;

        /// <summary>
        /// Generates <paramref name="size"/> byte array with cryptographically strong random data 
        /// </summary>
        /// <returns></returns>
        public static byte[] GenerateRandomSalt(ushort size)
        {
            byte[] salt = new byte[size];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        /// <summary>
        /// Generates key with size equal to <see cref="PasswordHelper.KeySize"/> and writes it to <paramref name="destination"/>
        /// </summary>
        /// <param name="password">Password to derive the key</param>
        /// <param name="salt">Salt to attach to password before deriving the key from</param>
        /// <param name="iterations">Number of iterations when deriving</param>
        /// <param name="destination">Destination to place derived key into</param>
        public static void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, Span<byte> destination)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, KeySize);
            Rfc2898DeriveBytes.Pbkdf2(password, salt, destination[..KeySize], iterations, HashAlgorithmName.SHA512);
        }
    }
}
