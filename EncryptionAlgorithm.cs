using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
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
            AES256GCM,
            AES128CCM,
            AES192CCM,
            AES256CCM,
            ChaCha20Poly1305,
            AES128EAX,
            AES192EAX,
            AES256EAX,
            Twofish128CTR,
            Twofish192CTR,
            Twofish256CTR,
            Threefish256CTR,
            Threefish512CTR,
            Threefish1024CTR,
        }

        internal static readonly Dictionary<EncryptionAlgorithmEnum, IEncryptionAlgorithmProvider> GetEncryptionAlgorithmProvider = new()
        {
            {EncryptionAlgorithmEnum.AES128GCM, new AesProvider(16, new AesGcm()) },
            {EncryptionAlgorithmEnum.AES192GCM, new AesProvider(24, new AesGcm()) },
            {EncryptionAlgorithmEnum.AES256GCM, new AesProvider(32, new AesGcm()) },
            {EncryptionAlgorithmEnum.AES128CCM, new AesProvider(16, new AesCcm()) },
            {EncryptionAlgorithmEnum.AES192CCM, new AesProvider(24, new AesCcm()) },
            {EncryptionAlgorithmEnum.AES256CCM, new AesProvider(32, new AesCcm()) },
            {EncryptionAlgorithmEnum.ChaCha20Poly1305, new ChaCha20Provider(32, new ChaCha20Poly1305()) },
            {EncryptionAlgorithmEnum.AES128EAX, new AesProvider(16, new AesEax()) },
            {EncryptionAlgorithmEnum.AES192EAX, new AesProvider(24, new AesEax()) },
            {EncryptionAlgorithmEnum.AES256EAX, new AesProvider(32, new AesEax()) },
            {EncryptionAlgorithmEnum.Twofish128CTR, new TwofishProvider(16, new TwofishCtr()) },
            {EncryptionAlgorithmEnum.Twofish192CTR, new TwofishProvider(24, new TwofishCtr()) },
            {EncryptionAlgorithmEnum.Twofish256CTR, new TwofishProvider(32, new TwofishCtr()) },
            {EncryptionAlgorithmEnum.Threefish256CTR, new ThreefishProvider(32, new ThreefishCtr(256)) },
            {EncryptionAlgorithmEnum.Threefish512CTR, new ThreefishProvider(64, new ThreefishCtr(512)) },
            {EncryptionAlgorithmEnum.Threefish1024CTR, new ThreefishProvider(128, new ThreefishCtr(1024)) }
        };

        internal static byte[] CalculateHMAC(ReadOnlySpan<byte> key, params byte[][] bytes)
        {
            byte[] hash = new byte[64];
            try
            {
                hash = SHA3_512.HashData(key);
                using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA3_512, hash);
                foreach (var chunk in bytes) hmac.AppendData(chunk);
                return hmac.GetHashAndReset();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
            
        }

        internal interface IEncryptionAlgorithm
        {
            public short ExtraEncryptionDataSize { get; }
            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key);
            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key);
        }

        private interface AESAlgorithm : IEncryptionAlgorithm;
        private interface ChaCha20Algorithm : IEncryptionAlgorithm;
        private interface TwoFishAlgorithm : IEncryptionAlgorithm;
        private interface ThreeFishAlgorithm : IEncryptionAlgorithm;


        internal class AesGcm : AESAlgorithm
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



        internal class AesCcm : AESAlgorithm
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
                    using (System.Security.Cryptography.AesCcm aesCcm = new System.Security.Cryptography.AesCcm(key))
                    {
                        aesCcm.Encrypt(iv, data, output, authentication);
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
                    using System.Security.Cryptography.AesCcm aesCcm = new System.Security.Cryptography.AesCcm(key);
                    aesCcm.Decrypt(iv, encryptedData, tag, decrypted);
                    return decrypted;
                }
                catch (Exception ex)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw VaultException.DecryptionFailed(ex);
                }
            }
        }

        internal class ChaCha20Poly1305 : ChaCha20Algorithm
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
                    using (System.Security.Cryptography.ChaCha20Poly1305 chaCha20 = new System.Security.Cryptography.ChaCha20Poly1305(key))
                    {
                        chaCha20.Encrypt(iv, data, output, authentication);
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
                    using System.Security.Cryptography.ChaCha20Poly1305 chaCha20 = new System.Security.Cryptography.ChaCha20Poly1305(key);
                    chaCha20.Decrypt(iv, encryptedData, tag, decrypted);
                    return decrypted;
                }
                catch (Exception ex)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw VaultException.DecryptionFailed(ex);
                }
            }
        }

        internal class AesEax : AESAlgorithm
        {
            public short ExtraEncryptionDataSize => 28;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to encrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to encrypt bytes, provided key was empty");

                byte[] iv = new byte[12];
                byte authenticationLength = 16;
                byte[] output = new byte[data.Length + authenticationLength];
                byte[] encrypted = new byte[iv.Length + output.Length];
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new EaxBlockCipher(new AesEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), authenticationLength * 8, iv);
                    cipher.Init(true, parameters);
                    int length = cipher.ProcessBytes(data, output);
                    cipher.DoFinal(output, length);
                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    Buffer.BlockCopy(output, 0, encrypted, iv.Length, output.Length);
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
                    CryptographicOperations.ZeroMemory(output);
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to decrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to decrypt bytes, provided key was empty");

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                byte authenticationLength = 16;
                ReadOnlySpan<byte> encryptedData = data[12..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] ivBytes = iv.ToArray();
                try
                {
                    var cipher = new EaxBlockCipher(new AesEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), authenticationLength * 8, ivBytes);
                    cipher.Init(false, parameters);
                    int length = cipher.ProcessBytes(encryptedData, decrypted);
                    cipher.DoFinal(decrypted, length);
                    return decrypted[..^authenticationLength];
                }
                catch (Exception ex)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw VaultException.DecryptionFailed(ex);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ivBytes);
                }
            }
        }

        internal class TwofishCtr : TwoFishAlgorithm
        {
            public short ExtraEncryptionDataSize => 76;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to encrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to encrypt bytes, provided key was empty");

                byte[] iv = new byte[12];
                byte[] authentication = new byte[64];
                byte[] output = new byte[data.Length];
                byte[] encrypted = new byte[iv.Length + output.Length + authentication.Length];
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new KCtrBlockCipher(new TwofishEngine());
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(true, parameters);
                    cipher.ProcessBytes(data, output);
                    authentication = CalculateHMAC(key, iv, output);
                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    Buffer.BlockCopy(output, 0, encrypted, iv.Length, output.Length);
                    Buffer.BlockCopy(authentication, 0, encrypted, iv.Length + output.Length, authentication.Length);
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

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to decrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to decrypt bytes, provided key was empty");

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                ReadOnlySpan<byte> encryptedData = data[12..^64];
                ReadOnlySpan<byte> tag = data[^64..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] calculatedTag = new byte[64];
                try
                {
                    byte[] ivTemp = null!;
                    byte[] encryptedTemp = null!;
                    try
                    {
                        ivTemp = iv.ToArray();
                        encryptedTemp = encryptedData.ToArray();
                        calculatedTag = CalculateHMAC(key, ivTemp, encryptedTemp);
                    }
                    finally
                    {
                        if (ivTemp is not null) CryptographicOperations.ZeroMemory(ivTemp);
                        if (encryptedTemp is not null) CryptographicOperations.ZeroMemory(encryptedTemp);
                    }
                    if (!CryptographicOperations.FixedTimeEquals(tag, calculatedTag)) throw new VaultException("Wrong HMAC authentication tag");
                    var cipher = new KCtrBlockCipher(new TwofishEngine());
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(false, parameters);
                    cipher.ProcessBytes(encryptedData, decrypted);
                    return decrypted;
                }
                catch (Exception ex)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw VaultException.DecryptionFailed(ex);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(calculatedTag);
                }
            }
        }

        internal class ThreefishCtr : ThreeFishAlgorithm
        {
            internal ThreefishCtr(int blockSizeInBits)
            {
                if(blockSizeInBits is not 256 and not 512 and not 1024) throw new ArgumentOutOfRangeException(nameof(blockSizeInBits));
                this.blockSizeInBits = blockSizeInBits;
            }

            private readonly int blockSizeInBits;
            public short ExtraEncryptionDataSize => 76;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to encrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to encrypt bytes, provided key was empty");

                byte[] iv = new byte[12];
                byte[] authentication = new byte[64];
                byte[] output = new byte[data.Length];
                byte[] encrypted = new byte[iv.Length + output.Length + authentication.Length];
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new KCtrBlockCipher(new ThreefishEngine(blockSizeInBits));
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(true, parameters);
                    cipher.ProcessBytes(data, output);
                    authentication = CalculateHMAC(key, iv, output);
                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    Buffer.BlockCopy(output, 0, encrypted, iv.Length, output.Length);
                    Buffer.BlockCopy(authentication, 0, encrypted, iv.Length + output.Length, authentication.Length);
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

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.Length == 0) throw new VaultException("Failed to decrypt bytes, provided data was empty");
                if (key.Length == 0) throw new VaultException("Failed to decrypt bytes, provided key was empty");

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                ReadOnlySpan<byte> encryptedData = data[12..^64];
                ReadOnlySpan<byte> tag = data[^64..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] calculatedTag = new byte[64];
                try
                {
                    byte[] ivTemp = null!;
                    byte[] encryptedTemp = null!;
                    try
                    {
                        ivTemp = iv.ToArray();
                        encryptedTemp = encryptedData.ToArray();
                        calculatedTag = CalculateHMAC(key, ivTemp, encryptedTemp);
                    }
                    finally
                    {
                        if (ivTemp is not null) CryptographicOperations.ZeroMemory(ivTemp);
                        if (encryptedTemp is not null) CryptographicOperations.ZeroMemory(encryptedTemp);
                    }
                    if (!CryptographicOperations.FixedTimeEquals(tag, calculatedTag)) throw new VaultException("Wrong HMAC authentication tag");
                    var cipher = new KCtrBlockCipher(new ThreefishEngine(blockSizeInBits));
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(false, parameters);
                    cipher.ProcessBytes(encryptedData, decrypted);
                    return decrypted;
                }
                catch (Exception ex)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw VaultException.DecryptionFailed(ex);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(calculatedTag);
                }
            }
        }



        internal interface IEncryptionAlgorithmProvider
        {
            public byte KeySize { get; }
            public IEncryptionAlgorithm EncryptionAlgorithm { get; }
        }

        private class AesProvider : IEncryptionAlgorithmProvider
        {
            public byte KeySize { get; }

            public IEncryptionAlgorithm EncryptionAlgorithm { get; }

            internal AesProvider(byte keySize, AESAlgorithm algorithm)
            {
                ArgumentNullException.ThrowIfNull(keySize);
                ArgumentNullException.ThrowIfNull(algorithm);
                if (keySize is not 16 and not 24 and not 32) throw new ArgumentOutOfRangeException(nameof(keySize));

                KeySize = keySize;
                EncryptionAlgorithm = algorithm;
            }
        }

        private class ChaCha20Provider : IEncryptionAlgorithmProvider
        {
            public byte KeySize { get; }

            public IEncryptionAlgorithm EncryptionAlgorithm { get; }

            internal ChaCha20Provider(byte keySize, ChaCha20Algorithm algorithm)
            {
                ArgumentNullException.ThrowIfNull(keySize);
                ArgumentNullException.ThrowIfNull(algorithm);
                if (keySize is not 32) throw new ArgumentOutOfRangeException(nameof(keySize));

                KeySize = keySize;
                EncryptionAlgorithm = algorithm;
            }
        }

        private class TwofishProvider : IEncryptionAlgorithmProvider
        {
            public byte KeySize { get; }

            public IEncryptionAlgorithm EncryptionAlgorithm { get; }

            internal TwofishProvider(byte keySize, TwoFishAlgorithm algorithm)
            {
                ArgumentNullException.ThrowIfNull(keySize);
                ArgumentNullException.ThrowIfNull(algorithm);
                if (keySize is not 16 and not 24 and not 32) throw new ArgumentOutOfRangeException(nameof(keySize));

                KeySize = keySize;
                EncryptionAlgorithm = algorithm;
            }
        }

        private class ThreefishProvider : IEncryptionAlgorithmProvider
        {
            public byte KeySize { get; }

            public IEncryptionAlgorithm EncryptionAlgorithm { get; }

            internal ThreefishProvider(byte keySize, ThreeFishAlgorithm algorithm)
            {
                ArgumentNullException.ThrowIfNull(keySize);
                ArgumentNullException.ThrowIfNull(algorithm);
                if (keySize is not 32 and not 64 and not 128) throw new ArgumentOutOfRangeException(nameof(keySize));

                KeySize = keySize;
                EncryptionAlgorithm = algorithm;
            }
        }
    }
}
