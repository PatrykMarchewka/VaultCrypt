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

        /// <summary>
        /// Converts string to <see cref="ISecureBuffer"/>
        /// </summary>
        /// <param name="stringToConvert">String to convert</param>
        /// <returns><see cref="ISecureBuffer"/> containing <paramref name="stringToConvert"/> in unmanaged memory type</returns>
        public static ISecureBuffer StringToSecureBuffer(string stringToConvert)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(stringToConvert);

            byte[] passwordBytes = Encoding.Unicode.GetBytes(stringToConvert); //C# uses Unicode (utf16) by default for strings
            ISecureBuffer buffer = SecureBuffer.Create(passwordBytes.Length);
            passwordBytes.CopyTo(buffer.AsSpan);
            CryptographicOperations.ZeroMemory(passwordBytes);
            return buffer;
        }
    }
}
