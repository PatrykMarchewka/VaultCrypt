using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.IO.Packaging;
using System.Linq;
using System.Printing.IndexedProperties;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Documents;

namespace VaultCrypt
{
    internal class Encryption
    {
        {
        internal static class AesGcmEncryption
        {
            internal static byte[] EncryptBytes(byte[] data, byte[] key)
            {
                using (AesGcm aesGcm = new AesGcm(key, 16))
                {
                    byte[] iv = new byte[12];
                    RandomNumberGenerator.Fill(iv);
                    byte[] authentication = new byte[16];
                    byte[] output = new byte[data.Length];

                    aesGcm.Encrypt(iv, data, output, authentication);

                    byte[] encrypted = new byte[iv.Length + authentication.Length + output.Length];


                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    Buffer.BlockCopy(authentication, 0, encrypted, iv.Length, authentication.Length);
                    Buffer.BlockCopy(output, 0, encrypted, iv.Length + authentication.Length, output.Length);
                    return encrypted;
                }
            }
        }


        







        }
    }
}
