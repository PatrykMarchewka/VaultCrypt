using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt
{
    internal class EncryptionAlgorithm
    {
        internal enum EncryptionAlgorithmEnum : byte
        {
            AES128GCM,
            AES192GCM,
            AES256GCM
        }

        internal static readonly Dictionary<EncryptionAlgorithmEnum, IEncryptionAlgorithmProvider> GetEncryptionAlgorithmProvider = new()
        {
            {EncryptionAlgorithmEnum.AES128GCM, new Aes128GcmProvider() },
            {EncryptionAlgorithmEnum.AES192GCM, new Aes192GcmProvider() },
            {EncryptionAlgorithmEnum.AES256GCM, new Aes256GcmProvider() }
        };

        internal interface IEncryptionAlgorithm
        {
            public short ExtraEncryptionDataSize { get; }
            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key);
            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key);
        }

        internal interface IEncryptionAlgorithmProvider
        {
            public byte KeySize { get; }
            public IEncryptionAlgorithm EncryptionAlgorithm { get; }
        }

        internal class AesGcm : IEncryptionAlgorithm
        {
            public short ExtraEncryptionDataSize => 28;
            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to encrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to encrypt bytes, provided key was empty");

                byte[] iv = new byte[12];
                byte[] authentication = new byte[16];
                byte[] output = new byte[data.Length];
                byte[] encrypted = new byte[iv.Length + authentication.Length + output.Length];
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, 16))
                    {
                        aesGcm.Encrypt(iv, data, output, authentication);
                    }
                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    Buffer.BlockCopy(authentication, 0, encrypted, iv.Length, authentication.Length);
                    Buffer.BlockCopy(output, 0, encrypted, iv.Length + authentication.Length, output.Length);
                    return encrypted;
                }
                catch (Exception ex)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw VaultException.EncryptionFailed(ex);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(iv);
                    CryptographicOperations.ZeroMemory(authentication);
                    CryptographicOperations.ZeroMemory(output);
                }
            }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="data"></param>
            /// <param name="key"></param>
            /// <returns></returns>
            /// <exception cref="VaultException">Thrown when decryption failed</exception>
            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to decrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to decrypt bytes, provided key was empty");

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                ReadOnlySpan<byte> tag = data.Slice(12, 16);
                ReadOnlySpan<byte> encryptedData = data.Slice(28);

                byte[] decrypted = new byte[encryptedData.Length];
                try
                {
                    using System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, 16);
                    aesGcm.Decrypt(iv, encryptedData, tag, decrypted);
                    return decrypted;
                }
                catch (Exception ex)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw VaultException.DecryptionFailed(ex);
                }
            }
        }

        internal class Aes128GcmProvider : IEncryptionAlgorithmProvider
        {
            public byte KeySize => 16;
            public IEncryptionAlgorithm EncryptionAlgorithm => new AesGcm();

        }

        internal class Aes192GcmProvider : IEncryptionAlgorithmProvider
        {
            public byte KeySize => 24;
            public IEncryptionAlgorithm EncryptionAlgorithm => new AesGcm();
        }

        internal class Aes256GcmProvider : IEncryptionAlgorithmProvider
        {
            public byte KeySize => 32;
            public IEncryptionAlgorithm EncryptionAlgorithm => new AesGcm();
        }
    }
}
