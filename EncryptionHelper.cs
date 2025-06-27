using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Printing.IndexedProperties;
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

        /// <summary>
        /// Encrypts file to another file
        /// </summary>
        /// <param name="filePath">Path of original file</param>
        /// <param name="outputFile">Where to save the file after encryption</param>
        /// <param name="password">Passowrd to encrypt file with</param>
        private static void EncryptToFile(string filePath, string outputFile, string password)
        {
            byte[] fileData = File.ReadAllBytes(filePath);
            byte[] encryptedData = EncryptBytes(fileData, password);
            using (FileStream fs = new FileStream(outputFile, FileMode.Create))
            {
                fs.Write(encryptedData, 0, encryptedData.Length);
            }
        }

        private static void DecryptFromFile(string inputFile, string outputFile, string password)
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

        /// <summary>
        /// Should be only called from EncryptBytes
        /// </summary>
        /// <param name="data">Byte array of original data</param>
        /// <param name="password">Password to encrypt with</param>
        /// <returns>Byte Array of encrypted data</returns>
        private static byte[] EncryptDataToBytes(byte[] data, string password)
        {
            using (AesGcm aesGcm = new AesGcm(DeriveKey(password), AesGcm.TagByteSizes.MaxSize))
            {
                byte[] iv = new byte[AesGcm.NonceByteSizes.MaxSize];
                RandomNumberGenerator.Fill(iv);
                byte[] output = new byte[data.Length];
                byte[] authentication = new byte[AesGcm.TagByteSizes.MaxSize];

                aesGcm.Encrypt(iv, data, output, authentication);

                byte[] encrypted = new byte[iv.Length + authentication.Length + output.Length];
                Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                Buffer.BlockCopy(authentication, 0, encrypted, iv.Length, authentication.Length);
                Buffer.BlockCopy(output, 0, encrypted, iv.Length + authentication.Length, output.Length);

                return encrypted;
            }
        }

        public static void EncryptFilesUsingThreads(string[] files, string output, string password)
        {
            foreach (var item in files)
            {
                //TODO: Fix it, placeholder for now
                Task.Run(() => EncryptToFile(item,"ffffff", password));
            }
        }

        /// <summary>
        /// Used to encrypt data to bytes
        /// </summary>
        /// <param name="bytes">Byte array of original data</param>
        /// <param name="password">Password to encrypt with</param>
        /// <returns>Byte array of encrypted data</returns>
        internal static byte[] EncryptBytes(byte[] bytes, string password)
        {
            return EncryptDataToBytes(bytes, password);
        }

        internal static byte[] EncryptFileToBytes(string filePath, string password)
        {
            byte[] fileData = File.ReadAllBytes(filePath);
            return EncryptBytes(fileData, password);
        }

        internal static byte[] DecryptBytes(byte[] encryptedMetadata, string password)
        {
            throw new NotImplementedException();
        }
    }
}
