using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Printing.IndexedProperties;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class EncryptionHelper
    {
        /// <summary>
        /// Generates unique salt
        /// </summary>
        /// <param name="saltSize">Size of the salt array</param>
        /// <returns>Array with unique salt</returns>
        private static byte[] GenerateUniqueSalt(int saltSize)
        {
            byte[] salt = new byte[saltSize];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        /// <summary>
        /// Derives key to use
        /// </summary>
        /// <param name="password">Password to use</param>
        /// <param name="options">Encryption options to use</param>
        /// <returns>Derived key</returns>
        public static byte[] DeriveKey(string password, EncryptionOptions options)
        {
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, options.Salt, options.Iterations, options.HashAlgorithm))
            {
                return pbkdf2.GetBytes(HashCodeMap[options.HashAlgorithm]);
            }
        }



        /// <summary>
        /// Used to store basic EncryptionOptions in the vault file.
        /// </summary>
        public readonly struct EncryptionOptions
        {
            public readonly int Iterations;
            public readonly HashAlgorithmName HashAlgorithm;
            public readonly byte[] Salt;
            public EncryptionOptions(byte[]? salt, HashAlgorithmName hashAlgorithm = default, int iterations = 10000)
            {
                HashAlgorithm = hashAlgorithm == default ? HashAlgorithmName.SHA256 : hashAlgorithm;
                Salt = salt ?? GenerateUniqueSalt(HashCodeMap[HashAlgorithm]);
                Iterations = iterations;
            }
        }





        /// <summary>
        /// Map holding salt size depending on the Hash algorhitm
        /// </summary>
        static readonly Dictionary<HashAlgorithmName, int> HashCodeMap = new()
        {
            [HashAlgorithmName.SHA256] = 32,
            [HashAlgorithmName.SHA384] = 48,
            [HashAlgorithmName.SHA512] = 64
        };




        /// <summary>
        /// Encrypts file and saves as another file
        /// </summary>
        /// <param name="filePath">Path of original file</param>
        /// <param name="outputFile">Where to save the file after encryption</param>
        /// <param name="key">Key to encrypt the data</param>
        private static void EncryptToFile(string filePath, string outputFile, byte[] key)
        {
            byte[] fileData = File.ReadAllBytes(filePath);
            byte[] encryptedData = EncryptBytes(fileData, key);
            using (FileStream fs = new FileStream(outputFile, FileMode.Create))
            {
                fs.Write(encryptedData);
            }
        }

        /// <summary>
        /// Decrypts file and saves as another file
        /// </summary>
        /// <param name="inputFile">Path of the encrypted file</param>
        /// <param name="outputFile">Where to save the file after decryption</param>
        /// <param name="key">Key to decrypt the data</param>
        private static void DecryptFromFile(string inputFile, string outputFile, byte[] key)
        {
            byte[] fileData = File.ReadAllBytes(inputFile);
            byte[] decryptedData = DecryptBytes(fileData, key);
            using (FileStream fs = new FileStream(outputFile, FileMode.Create))
            {
                fs.Write(decryptedData);
            }
        }

        /// <summary>
        /// Should be only called from <see cref="EncryptBytes(byte[])"/>
        /// </summary>
        /// <param name="data">Byte array of original data</param>
        /// <param name="key">Key to encrypt the data</param>
        /// <returns>Byte array of encrypted data</returns>
        private static byte[] EncryptDataToBytes(byte[] data, byte[] key)
        {
            using (AesGcm aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
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

        /// <summary>
        /// Should only be called from <see cref="DecryptBytes(byte[])"/>
        /// </summary>
        /// <param name="data">Byte array of encrypted data</param>
        /// <param name="key">Key to decrypt the data</param>
        /// <returns></returns>
        private static byte[] DecryptDataToBytes(byte[] data, byte[] key)
        {
            Span<byte> iv = data.AsSpan(0, 12);
            Span<byte> tag = data.AsSpan(12, 16);
            Span<byte> encryptedData = data.AsSpan(28);

            byte[] decrypted = new byte[encryptedData.Length];

            using (AesGcm aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
            {
                aesGcm.Decrypt(iv, encryptedData, tag, decrypted);
            }
            return decrypted;
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
        /// Encrypts given bytes
        /// </summary>
        /// <param name="bytes">Byte array of original data</param>
        /// <param name="key">Key to encrypt the data</param>
        /// <returns>Byte array of encrypted data</returns>
        internal static byte[] EncryptBytes(byte[] bytes, byte[] key)
        {
            return EncryptDataToBytes(bytes, key);
        }

        /// <summary>
        /// Encrypts entire file at once
        /// </summary>
        /// <param name="filePath">File to encrypt</param>
        /// <param name="key">Key to encrypt the data</param>
        /// <returns>Byte array of encrypted data</returns>
        internal static byte[] EncryptFileToBytes(string filePath, byte[] key)
        {
            byte[] fileData = File.ReadAllBytes(filePath);
            return EncryptBytes(fileData, key);
        }

        /// <summary>
        /// Decrypts given bytes
        /// </summary>
        /// <param name="encryptedData">Byte array of encrypted data</param>
        /// <param name="key">Key to decrypt the data</param>
        /// <returns></returns>
        internal static byte[] DecryptBytes(byte[] encryptedData, byte[] key)
        {
            return DecryptDataToBytes(encryptedData, key);
        }

        /// <summary>
        /// Decrypts entire file at once
        /// </summary>
        /// <param name="filePath">File to decrypt</param>
        /// <param name="key">Key to decrypt the data</param>
        /// <returns></returns>
        internal static byte[] DecryptFileToBytes(string filePath, byte[] key)
        {
            byte[] fileData = File.ReadAllBytes(filePath);
            return DecryptBytes(fileData, key);
        }
    }
}
