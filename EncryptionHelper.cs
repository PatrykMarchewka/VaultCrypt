using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class EncryptionHelper
    {
        private static byte[] DeriveKey(string password)
        {
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, 16, 10000, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32);
            }
        }


        private static void EncryptFile(string filePath, string outputFile, string password)
        {
            using (AesGcm aesGcm = new AesGcm(DeriveKey(password), 16))
            {
                byte[] iv = new byte[AesGcm.NonceByteSizes.MaxSize];
                RandomNumberGenerator.Fill(iv);

                byte[] plaintext = File.ReadAllBytes(filePath);
                byte[] output = new byte[plaintext.Length];
                byte[] authentication = new byte[AesGcm.TagByteSizes.MaxSize];

                aesGcm.Encrypt(iv, plaintext, output, authentication);

                using (FileStream fs = new FileStream(outputFile, FileMode.Create))
                {
                    fs.Write(iv, 0, iv.Length);
                    fs.Write(authentication, 0, authentication.Length);
                    fs.Write(output, 0, output.Length);
                }


            }
        }

        private static void DecryptFile(string inputFile, string outputFile, string password)
        {
            using (FileStream fs = new FileStream(inputFile, FileMode.Open))
            {
                byte[] iv = new byte[AesGcm.NonceByteSizes.MaxSize];
                byte[] authentication = new byte[AesGcm.TagByteSizes.MaxSize];
                byte[] encrypted = new byte[fs.Length - iv.Length - authentication.Length];

                fs.Read(iv, 0, iv.Length);
                fs.Read(authentication, 0, authentication.Length);
                fs.Read(encrypted, 0, encrypted.Length);

                byte[] plaintext = new byte[encrypted.Length];

                using (AesGcm aesGcm = new AesGcm(DeriveKey(password), 16))
                {
                    aesGcm.Decrypt(iv, encrypted, authentication, plaintext);
                }

                File.WriteAllBytes(outputFile, plaintext);
            }
        }

        public static void EncryptFilesUsingThreads(string[] files, string output, string password)
        {
            foreach (var item in files)
            {
                //TODO: Fix it, placeholder for now
                Task.Run(() => EncryptFile(item,"ffffff", password));
            }
        }

        internal static byte[] EncryptBytes(byte[] bytes, string password)
        {
            throw new NotImplementedException();
        }

        internal static byte[] DecryptBytes(byte[] encryptedMetadata, string password)
        {
            throw new NotImplementedException();
        }
    }
}
