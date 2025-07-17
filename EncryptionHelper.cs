using System;
using System.Buffers.Binary;
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
        public readonly struct EncryptionOptions
        {
            public readonly string Password;
            public readonly int Iterations;
            public readonly HashAlgorithmName HashAlgorithm;
            public readonly byte[] Salt;
            public readonly byte[] Key;

            public EncryptionOptions(string password, HashAlgorithmName hashAlgorithm, byte[] salt, byte[] key, int iterations = 10000)
                Password = password;
                Iterations = iterations;
                HashAlgorithm = hashAlgorithm;
                Salt = GenerateUniqueSalt(HashCodeMap[HashAlgorithm]);
                Key = DeriveKey(Password, Salt, HashAlgorithm, Iterations);
            }

            private static byte[] GenerateUniqueSalt(int saltSize)
            {
                byte[] salt = new byte[saltSize];
                RandomNumberGenerator.Fill(salt);
                return salt;
            }
            private static byte[] DeriveKey(string password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 10000)
            {
                using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, hashAlgorithm))
                {
                    return pbkdf2.GetBytes(HashCodeMap[hashAlgorithm]);
                }
            }
        }




        static readonly Dictionary<HashAlgorithmName, int> HashCodeMap = new()
        {
            [HashAlgorithmName.SHA256] = 32,
            [HashAlgorithmName.SHA384] = 48,
            [HashAlgorithmName.SHA512] = 64
        };




        /// <summary>
        /// Encrypts file to another file
        /// </summary>
        /// <param name="filePath">Path of original file</param>
        /// <param name="outputFile">Where to save the file after encryption</param>
        /// <param name="options">Encryption options struct</param>
        private static void EncryptToFile(string filePath, string outputFile, EncryptionOptions options)
        {
            byte[] fileData = File.ReadAllBytes(filePath);
            byte[] encryptedData = EncryptBytes(fileData, password);
            using (FileStream fs = new FileStream(outputFile, FileMode.Create))
            {
                fs.Write(encryptedData, 0, encryptedData.Length);
            }
        }

        private static void DecryptFromFile(string inputFile, string outputFile, EncryptionOptions options)
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

                using (AesGcm aesGcm = new AesGcm(options.Key, AesGcm.TagByteSizes.MaxSize))
                {
                    aesGcm.Decrypt(iv, encrypted, authentication, plaintext);
                }

                File.WriteAllBytes(outputFile, plaintext);
            }
        }

        /// <summary>
        /// Should be only called from <see cref="EncryptBytes(byte[], EncryptionOptions)"/>
        /// </summary>
        /// <param name="data">Byte array of original data</param>
        /// <param name="options">Encryption options struct</param>
        /// <returns>Byte array of encrypted data</returns>
        private static byte[] EncryptDataToBytes(byte[] data, EncryptionOptions options)
        {
            using (AesGcm aesGcm = new AesGcm(options.Key, AesGcm.TagByteSizes.MaxSize))
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



        //UNUSED FOR NOW!
        //public static void EncryptFilesUsingThreads(string[] files, string output, string password)
        //{
        //    foreach (var item in files)
        //    {
        //        //TODO: Fix it, placeholder for now
        //        Task.Run(() => EncryptToFile(item,"ffffff", password));
        //    }
        //}


        /// <summary>
        /// Used to encrypt data to bytes
        /// </summary>
        /// <param name="bytes">Byte array of original data</param>
        /// <param name="options">Encryption options struct</param>
        /// <returns>Byte array of encrypted data</returns>
        internal static byte[] EncryptBytes(byte[] bytes, EncryptionOptions options)
        {
            return EncryptDataToBytes(bytes, options);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="filePath">File to encrypt</param>
        /// <param name="options">Encryption options struct</param>
        /// <returns>Byte array of encrypted data</returns>
        internal static byte[] EncryptFileToBytes(string filePath, EncryptionOptions options)
        {
            byte[] fileData = File.ReadAllBytes(filePath);
            return EncryptBytes(fileData, options);
        }

        internal static byte[] DecryptBytes(byte[] encryptedMetadata, string password)
        {
            throw new NotImplementedException();
        }
    }
}
