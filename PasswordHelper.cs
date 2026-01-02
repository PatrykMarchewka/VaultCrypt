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
        /// Generates 32 byte array with cryptographically strong random data 
        /// </summary>
        /// <returns></returns>
        internal static byte[] GenerateRandomSalt()
        {
            byte[] salt = new byte[32];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        internal static byte[] DeriveKey(byte[] password)
        {
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, VaultSession.SALT, VaultSession.ITERATIONS, HashAlgorithmName.SHA512))
            {
                return pbkdf2.GetBytes(128);
            }
        }

        internal static byte[] GetSlicedKey(byte keySize)
        {
            return VaultSession.KEY.AsSpan(0, keySize).ToArray();
        }

        internal static byte[] GetSlicedKey(EncryptionOptions.EncryptionProtocol protocol)
        {
            return GetSlicedKey(EncryptionOptions.GetEncryptionProtocolInfo[protocol].keySize);
        }

        internal static byte[] SecureStringToUTF8ToBytes(SecureString secureString)
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

                //Convert to utf8
                //TODO: Try to fix this, we store string for a period of time until GC cleans it, so the password is temporarily in memory
                string temp = Encoding.Unicode.GetString(utf16Bytes);
                byte[] utf8Bytes = Encoding.UTF8.GetBytes(temp);

                CryptographicOperations.ZeroMemory(utf16Bytes);
                return utf8Bytes;
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
