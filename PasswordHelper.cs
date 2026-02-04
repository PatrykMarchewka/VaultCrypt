using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class PasswordHelper
    {
        /// <summary>
        /// Generates <paramref name="size"/> byte array with cryptographically strong random data 
        /// </summary>
        /// <returns></returns>
        internal static byte[] GenerateRandomSalt(short size)
        {
            byte[] salt = new byte[size];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        internal static byte[] DeriveKey(byte[] password, byte[] salt, int iterations)
        {
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512))
            {
                return pbkdf2.GetBytes(128);
            }
        }

        internal static ReadOnlyMemory<byte> GetSlicedKey(byte keySize)
        {
            return VaultSession.CurrentSession.KEY.AsMemory(0, keySize);
        }

        internal static ReadOnlyMemory<byte> GetSlicedKey(EncryptionAlgorithm.EncryptionAlgorithmEnum encryptionAlgorithmEnum)
        {
            return GetSlicedKey(EncryptionAlgorithm.GetEncryptionAlgorithmProvider[encryptionAlgorithmEnum].KeySize);
        }

        internal static byte[] SecureStringToBytes(SecureString secureString)
        {
            //Null Pointer
            IntPtr bstrPointer = IntPtr.Zero;
            try
            {
                //Decrypt SecureString into BSTR in UTF18 encoding and is saved as pointer to first character
                //BSTR = Binary string [4 byte length][UTF16 characters][null terminator (\0\0)]
                bstrPointer = Marshal.SecureStringToBSTR(secureString);

                //Read the length before the first character
                int length = Marshal.ReadInt32(bstrPointer, -4);

                byte[] utf16Bytes = new byte[length];
                Marshal.Copy(bstrPointer, utf16Bytes, 0, length);
                return utf16Bytes;
            }
            finally
            {
                if (bstrPointer != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstrPointer);
                }
            }
        }



    }
}
