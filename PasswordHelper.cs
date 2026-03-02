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
    public class PasswordHelper
    {
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

        public static byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations)
        {
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, 128);
        }

        public static ReadOnlyMemory<byte> GetSlicedKey(byte keySize)
        {
            if (keySize > VaultSession.CurrentSession.KEY.Length) throw new ArgumentOutOfRangeException("Requested bigger slice than the length of entire key");
            return VaultSession.CurrentSession.KEY.AsMemory(0, keySize);
        }

        public static byte[] SecureStringToBytes(SecureString secureString)
        {
            //Null Pointer
            IntPtr bstrPointer = IntPtr.Zero;
            try
            {
                //Decrypt SecureString into BSTR in UTF16 encoding and is saved as pointer to first character
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
