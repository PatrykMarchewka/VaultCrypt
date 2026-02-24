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
    public class EncryptionAlgorithm
    {
        public sealed record EncryptionAlgorithmInfo(byte ID, string Name, Func<IEncryptionAlgorithmProvider> provider)
        {
            internal static readonly EncryptionAlgorithmInfo AES128GCM = new(0, "AES-128-GCM", () => new AesProvider(16, new AesGcm()));
            internal static readonly EncryptionAlgorithmInfo AES192GCM = new(1, "AES-192-GCM", () => new AesProvider(24, new AesGcm()));
            internal static readonly EncryptionAlgorithmInfo AES256GCM = new(2, "AES-256-GCM", () => new AesProvider(32, new AesGcm()));
            internal static readonly EncryptionAlgorithmInfo AES128CCM = new(3, "AES-128-CCM", () => new AesProvider(16, new AesCcm()));
            internal static readonly EncryptionAlgorithmInfo AES192CCM = new(4, "AES-192-CCM", () => new AesProvider(24, new AesCcm()));
            internal static readonly EncryptionAlgorithmInfo AES256CCM = new(5, "AES-256-CCM", () => new AesProvider(32, new AesCcm()));
            internal static readonly EncryptionAlgorithmInfo ChaCha20Poly1305 = new(6, "ChaCha20-Poly1305", () => new ChaCha20Provider(32, new ChaCha20Poly1305()));
            internal static readonly EncryptionAlgorithmInfo AES128EAX = new(7, "AES-128-EAX", () => new AesProvider(16, new AesEax()));
            internal static readonly EncryptionAlgorithmInfo AES192EAX = new(8, "AES-192-EAX", () => new AesProvider(24, new AesEax()));
            internal static readonly EncryptionAlgorithmInfo AES256EAX = new(9, "AES-256-EAX", () => new AesProvider(32, new AesEax()));
            internal static readonly EncryptionAlgorithmInfo Twofish128CTR = new(10, "Twofish-128-CTR", () => new TwofishProvider(16, new TwofishCtr()));
            internal static readonly EncryptionAlgorithmInfo Twofish192CTR = new(11, "Twofish-192-CTR", () => new TwofishProvider(24, new TwofishCtr()));
            internal static readonly EncryptionAlgorithmInfo Twofish256CTR = new(12, "Twofish-256-CTR", () => new TwofishProvider(32, new TwofishCtr()));
            internal static readonly EncryptionAlgorithmInfo Threefish256CTR = new(13, "Threefish-128-CTR", () => new ThreefishProvider(32, new ThreefishCtr(256)));
            internal static readonly EncryptionAlgorithmInfo Threefish512CTR = new(14, "Threefish-192-CTR", () => new ThreefishProvider(64, new ThreefishCtr(512)));
            internal static readonly EncryptionAlgorithmInfo Threefish1024CTR = new(15, "Threefish-256-CTR", () => new ThreefishProvider(128, new ThreefishCtr(1024)));
            internal static readonly EncryptionAlgorithmInfo Serpent128GCM = new(16, "Serpent-128-GCM", () => new SerpentProvider(16, new SerpentGcm()));
            internal static readonly EncryptionAlgorithmInfo Serpent192GCM = new(17, "Serpent-192-GCM", () => new SerpentProvider(24, new SerpentGcm()));
            internal static readonly EncryptionAlgorithmInfo Serpent256GCM = new(18, "Serpent-256-GCM", () => new SerpentProvider(32, new SerpentGcm()));
            internal static readonly EncryptionAlgorithmInfo Serpent128CTR = new(19, "Serpent-128-CTR", () => new SerpentProvider(16, new SerpentCtr()));
            internal static readonly EncryptionAlgorithmInfo Serpent192CTR = new(20, "Serpent-192-CTR", () => new SerpentProvider(24, new SerpentCtr()));
            internal static readonly EncryptionAlgorithmInfo Serpent256CTR = new(21, "Serpent-256-CTR", () => new SerpentProvider(32, new SerpentCtr()));
            internal static readonly EncryptionAlgorithmInfo Camelia128GCM = new(22, "Camelia-128-GCM", () => new CameliaProvider(16, new CameliaGcm()));
            internal static readonly EncryptionAlgorithmInfo Camelia192GCM = new(23, "Camelia-192-GCM", () => new CameliaProvider(24, new CameliaGcm()));
            internal static readonly EncryptionAlgorithmInfo Camelia256GCM = new(24, "Camelia-256-GCM", () => new CameliaProvider(32, new CameliaGcm()));
            internal static readonly EncryptionAlgorithmInfo Camelia128OCB = new(25, "Camelia-128-OCB", () => new CameliaProvider(16, new CameliaOcb()));
            internal static readonly EncryptionAlgorithmInfo Camelia192OCB = new(26, "Camelia-192-OCB", () => new CameliaProvider(24, new CameliaOcb()));
            internal static readonly EncryptionAlgorithmInfo Camelia256OCB = new(27, "Camelia-256-OCB", () => new CameliaProvider(32, new CameliaOcb()));
            internal static readonly EncryptionAlgorithmInfo Camelia128CTR = new(28, "Camelia-128-CTR", () => new CameliaProvider(16, new CameliaCtr()));
            internal static readonly EncryptionAlgorithmInfo Camelia192CTR = new(29, "Camelia-192-CTR", () => new CameliaProvider(24, new CameliaCtr()));
            internal static readonly EncryptionAlgorithmInfo Camelia256CTR = new(30, "Camelia-256-CTR", () => new CameliaProvider(32, new CameliaCtr()));
            internal static readonly EncryptionAlgorithmInfo XSalsa20 = new(31, "XSalsa20", () => new XSalsa20Provider(32, new XSalsa20()));

            public override string ToString() => Name;
        }

        public static readonly IReadOnlyDictionary<byte, EncryptionAlgorithmInfo> GetEncryptionAlgorithmInfo = _BuildDictionary();

        private static IReadOnlyDictionary<byte, EncryptionAlgorithmInfo> _BuildDictionary()
        {
            return typeof(EncryptionAlgorithmInfo).GetFields(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)
                .Where(info => info.FieldType == typeof(EncryptionAlgorithmInfo))
                .Select(info => (EncryptionAlgorithmInfo)info.GetValue(null)!) //Null because there is no instance, its a static field
                .ToDictionary(info => info.ID);
        }

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

        internal static byte[] CalculateHMAC(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> cipherText)
        {
            byte[] ivSeg = iv.ToArray();
            byte[] cipherSeg = cipherText.ToArray();
            try
            {
                return CalculateHMAC(key, ivSeg, cipherSeg);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ivSeg);
                CryptographicOperations.ZeroMemory(cipherSeg);
            }
        }

        public interface IEncryptionAlgorithm
        {
            public short ExtraEncryptionDataSize { get; }
            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key);
            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key);
        }

        private interface AESAlgorithm : IEncryptionAlgorithm;
        private interface ChaCha20Algorithm : IEncryptionAlgorithm;
        private interface TwoFishAlgorithm : IEncryptionAlgorithm;
        private interface ThreeFishAlgorithm : IEncryptionAlgorithm;
        private interface SerpentAlgorithm : IEncryptionAlgorithm;
        private interface CameliaAlgorithm : IEncryptionAlgorithm;
        private interface XSalsa20Algorithm : IEncryptionAlgorithm;


        public class AesGcm : AESAlgorithm
        {
            public short ExtraEncryptionDataSize => 28;
            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));


                byte ivLength = 12;
                byte authenticationLength = 16;
                byte[] encrypted = new byte[ivLength + authenticationLength + data.Length];

                Span<byte> iv = encrypted.AsSpan(0, ivLength);
                Span<byte> authentication = encrypted.AsSpan(ivLength, authenticationLength);
                Span<byte> output = encrypted.AsSpan(ivLength + authenticationLength);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, 16))
                    {
                        aesGcm.Encrypt(iv, data, output, authentication);
                    }
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
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
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

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
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
            }
        }



        public class AesCcm : AESAlgorithm
        {
            public short ExtraEncryptionDataSize => 28;
            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte ivLength = 12;
                byte authenticationLength = 16;
                byte[] encrypted = new byte[ivLength + authenticationLength + data.Length];

                Span<byte> iv = encrypted.AsSpan(0, ivLength);
                Span<byte> authentication = encrypted.AsSpan(ivLength, authenticationLength);
                Span<byte> output = encrypted.AsSpan(ivLength + authenticationLength);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    using (System.Security.Cryptography.AesCcm aesCcm = new System.Security.Cryptography.AesCcm(key))
                    {
                        aesCcm.Encrypt(iv, data, output, authentication);
                    }
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

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
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
            }
        }

        public class ChaCha20Poly1305 : ChaCha20Algorithm
        {
            public short ExtraEncryptionDataSize => 28;
            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte ivLength = 12;
                byte authenticationLength = 16;
                byte[] encrypted = new byte[ivLength + authenticationLength + data.Length];

                Span<byte> iv = encrypted.AsSpan(0, ivLength);
                Span<byte> authentication = encrypted.AsSpan(ivLength, authenticationLength);
                Span<byte> output = encrypted.AsSpan(ivLength + authenticationLength);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    using (System.Security.Cryptography.ChaCha20Poly1305 chaCha20 = new System.Security.Cryptography.ChaCha20Poly1305(key))
                    {
                        chaCha20.Encrypt(iv, data, output, authentication);
                    }
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

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
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
            }
        }

        public class AesEax : AESAlgorithm
        {
            public short ExtraEncryptionDataSize => 28;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte[] iv = new byte[12];
                byte authenticationLength = 16;
                byte[] encrypted = new byte[iv.Length + data.Length + authenticationLength];

                Span<byte> output = encrypted.AsSpan(iv.Length, data.Length + authenticationLength);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new EaxBlockCipher(new AesEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), authenticationLength * 8, iv);
                    cipher.Init(true, parameters);
                    int length = cipher.ProcessBytes(data, output);
                    cipher.DoFinal(output.Slice(length));
                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(iv);
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

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
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ivBytes);
                }
            }
        }

        public class TwofishCtr : TwoFishAlgorithm
        {
            public short ExtraEncryptionDataSize => 76;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte ivLength = 12;
                byte authenticationLength = 64;
                byte[] encrypted = new byte[ivLength + authenticationLength + data.Length];

                Span<byte> iv = encrypted.AsSpan(0, ivLength);
                Span<byte> authentication = encrypted.AsSpan(ivLength + data.Length, authenticationLength);
                Span<byte> output = encrypted.AsSpan(ivLength, data.Length);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new KCtrBlockCipher(new TwofishEngine());
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(true, parameters);
                    cipher.ProcessBytes(data, output);

                    byte[] hmac = new byte[64];
                    try
                    {
                        hmac = CalculateHMAC(key, iv, output);
                        hmac.AsSpan().CopyTo(authentication);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(hmac);
                    }
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                ReadOnlySpan<byte> encryptedData = data[12..^64];
                ReadOnlySpan<byte> tag = data[^64..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] calculatedTag = new byte[64];
                try
                {
                    calculatedTag = CalculateHMAC(key, iv, encryptedData);
                    if (!CryptographicOperations.FixedTimeEquals(tag, calculatedTag)) throw new VaultException(VaultException.ErrorContext.Decrypt, VaultException.ErrorReason.WrongHMAC);
                    var cipher = new KCtrBlockCipher(new TwofishEngine());
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(false, parameters);
                    cipher.ProcessBytes(encryptedData, decrypted);
                    return decrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(calculatedTag);
                }
            }
        }

        public class ThreefishCtr : ThreeFishAlgorithm
        {
            public ThreefishCtr(int blockSizeInBits)
            {
                if(blockSizeInBits is not (256 or 512 or 1024)) throw new ArgumentOutOfRangeException(nameof(blockSizeInBits));
                this.blockSizeInBits = blockSizeInBits;
            }

            private readonly int blockSizeInBits;
            public short ExtraEncryptionDataSize => 76;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte ivLength = 12;
                byte authenticationLength = 64;
                byte[] encrypted = new byte[ivLength + authenticationLength + data.Length];

                Span<byte> iv = encrypted.AsSpan(0, ivLength);
                Span<byte> authentication = encrypted.AsSpan(ivLength + data.Length, authenticationLength);
                Span<byte> output = encrypted.AsSpan(ivLength, data.Length);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new KCtrBlockCipher(new ThreefishEngine(blockSizeInBits));
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(true, parameters);
                    cipher.ProcessBytes(data, output);
                    byte[] hmac = new byte[64];
                    try
                    {
                        hmac = CalculateHMAC(key, iv, output);
                        hmac.AsSpan().CopyTo(authentication);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(hmac);
                    }
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                ReadOnlySpan<byte> encryptedData = data[12..^64];
                ReadOnlySpan<byte> tag = data[^64..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] calculatedTag = new byte[64];
                try
                {
                    calculatedTag = CalculateHMAC(key, iv, encryptedData);
                    if (!CryptographicOperations.FixedTimeEquals(tag, calculatedTag)) throw new VaultException(VaultException.ErrorContext.Decrypt, VaultException.ErrorReason.WrongHMAC);
                    var cipher = new KCtrBlockCipher(new ThreefishEngine(blockSizeInBits));
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(false, parameters);
                    cipher.ProcessBytes(encryptedData, decrypted);
                    return decrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(calculatedTag);
                }
            }
        }

        public class SerpentGcm : SerpentAlgorithm
        {
            public short ExtraEncryptionDataSize => 28;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte[] iv = new byte[12];
                byte authenticationLength = 16;
                byte[] encrypted = new byte[iv.Length + data.Length + authenticationLength];

                Span<byte> output = encrypted.AsSpan(iv.Length, data.Length + authenticationLength);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new GcmBlockCipher(new SerpentEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), authenticationLength * 8, iv);
                    cipher.Init(true, parameters);
                    int length = cipher.ProcessBytes(data, output);
                    cipher.DoFinal(output.Slice(length));
                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(iv);
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                byte authenticationLength = 16;
                ReadOnlySpan<byte> encryptedData = data[12..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] ivBytes = iv.ToArray();
                try
                {
                    var cipher = new GcmBlockCipher(new SerpentEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), authenticationLength * 8, ivBytes);
                    cipher.Init(false, parameters);
                    int length = cipher.ProcessBytes(encryptedData, decrypted);
                    cipher.DoFinal(decrypted, length);
                    return decrypted[..^authenticationLength];
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ivBytes);
                }
            }
        }

        public class SerpentCtr : SerpentAlgorithm
        {
            public short ExtraEncryptionDataSize => 76;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte ivLength = 12;
                byte authenticationLength = 64;
                byte[] encrypted = new byte[ivLength + authenticationLength + data.Length];

                Span<byte> iv = encrypted.AsSpan(0, ivLength);
                Span<byte> authentication = encrypted.AsSpan(ivLength + data.Length, authenticationLength);
                Span<byte> output = encrypted.AsSpan(ivLength, data.Length);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new KCtrBlockCipher(new SerpentEngine());
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(true, parameters);
                    cipher.ProcessBytes(data, output);
                    byte[] hmac = new byte[64];
                    try
                    {
                        hmac = CalculateHMAC(key, iv, output);
                        hmac.AsSpan().CopyTo(authentication);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(hmac);
                    }
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                ReadOnlySpan<byte> encryptedData = data[12..^64];
                ReadOnlySpan<byte> tag = data[^64..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] calculatedTag = new byte[64];
                try
                {
                    calculatedTag = CalculateHMAC(key, iv, encryptedData);
                    if (!CryptographicOperations.FixedTimeEquals(tag, calculatedTag)) throw new VaultException(VaultException.ErrorContext.Decrypt, VaultException.ErrorReason.WrongHMAC);
                    var cipher = new KCtrBlockCipher(new SerpentEngine());
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(false, parameters);
                    cipher.ProcessBytes(encryptedData, decrypted);
                    return decrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(calculatedTag);
                }
            }
        }

        public class CameliaGcm : CameliaAlgorithm
        {
            public short ExtraEncryptionDataSize => 28;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte[] iv = new byte[12];
                byte authenticationLength = 16;
                byte[] encrypted = new byte[iv.Length + data.Length + authenticationLength];

                Span<byte> output = encrypted.AsSpan(iv.Length, data.Length + authenticationLength);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new GcmBlockCipher(new CamelliaEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), authenticationLength * 8, iv);
                    cipher.Init(true, parameters);
                    int length = cipher.ProcessBytes(data, output);
                    cipher.DoFinal(output.Slice(length));
                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(iv);
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                byte authenticationLength = 16;
                ReadOnlySpan<byte> encryptedData = data[12..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] ivBytes = iv.ToArray();
                try
                {
                    var cipher = new GcmBlockCipher(new CamelliaEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), authenticationLength * 8, ivBytes);
                    cipher.Init(false, parameters);
                    int length = cipher.ProcessBytes(encryptedData, decrypted);
                    cipher.DoFinal(decrypted, length);
                    return decrypted[..^authenticationLength];
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ivBytes);
                }
            }
        }

        public class CameliaOcb : CameliaAlgorithm
        {
            public short ExtraEncryptionDataSize => 28;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte[] iv = new byte[12];
                byte authenticationLength = 16;
                byte[] encrypted = new byte[iv.Length + data.Length + authenticationLength];

                Span<byte> output = encrypted.AsSpan(iv.Length, data.Length + authenticationLength);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new OcbBlockCipher(new CamelliaEngine(), new CamelliaEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), authenticationLength * 8, iv);
                    cipher.Init(true, parameters);
                    int length = cipher.ProcessBytes(data, output);
                    cipher.DoFinal(output.Slice(length));
                    Buffer.BlockCopy(iv, 0, encrypted, 0, iv.Length);
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(iv);
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                byte authenticationLength = 16;
                ReadOnlySpan<byte> encryptedData = data[12..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] ivBytes = iv.ToArray();
                try
                {
                    var cipher = new OcbBlockCipher(new CamelliaEngine(), new CamelliaEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), authenticationLength * 8, ivBytes);
                    cipher.Init(false, parameters);
                    int length = cipher.ProcessBytes(encryptedData, decrypted);
                    cipher.DoFinal(decrypted, length);
                    return decrypted[..^authenticationLength];
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ivBytes);
                }
            }
        }

        public class CameliaCtr : CameliaAlgorithm
        {
            public short ExtraEncryptionDataSize => 76;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte ivLength = 12;
                byte authenticationLength = 64;
                byte[] encrypted = new byte[ivLength + authenticationLength + data.Length];

                Span<byte> iv = encrypted.AsSpan(0, ivLength);
                Span<byte> authentication = encrypted.AsSpan(ivLength + data.Length, authenticationLength);
                Span<byte> output = encrypted.AsSpan(ivLength, data.Length);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new KCtrBlockCipher(new CamelliaEngine());
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(true, parameters);
                    cipher.ProcessBytes(data, output);
                    byte[] hmac = new byte[64];
                    try
                    {
                        hmac = CalculateHMAC(key, iv, output);
                        hmac.AsSpan().CopyTo(authentication);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(hmac);
                    }
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                ReadOnlySpan<byte> iv = data.Slice(0, 12);
                ReadOnlySpan<byte> encryptedData = data[12..^64];
                ReadOnlySpan<byte> tag = data[^64..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] calculatedTag = new byte[64];
                try
                {
                    calculatedTag = CalculateHMAC(key, iv, encryptedData);
                    if (!CryptographicOperations.FixedTimeEquals(tag, calculatedTag)) throw new VaultException(VaultException.ErrorContext.Decrypt, VaultException.ErrorReason.WrongHMAC);
                    var cipher = new KCtrBlockCipher(new CamelliaEngine());
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(false, parameters);
                    cipher.ProcessBytes(encryptedData, decrypted);
                    return decrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(calculatedTag);
                }
            }
        }

        public class XSalsa20 : XSalsa20Algorithm
        {
            public short ExtraEncryptionDataSize => 88;

            public byte[] EncryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                byte ivLength = 24;
                byte authenticationLength = 64;
                byte[] encrypted = new byte[ivLength + authenticationLength + data.Length];

                Span<byte> iv = encrypted.AsSpan(0, ivLength);
                Span<byte> authentication = encrypted.AsSpan(ivLength + data.Length, authenticationLength);
                Span<byte> output = encrypted.AsSpan(ivLength, data.Length);
                try
                {
                    RandomNumberGenerator.Fill(iv);
                    var cipher = new XSalsa20Engine();
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(true, parameters);
                    cipher.ProcessBytes(data, output);
                    byte[] hmac = new byte[64];
                    try
                    {
                        hmac = CalculateHMAC(key, iv, output);
                        hmac.AsSpan().CopyTo(authentication);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(hmac);
                    }
                    return encrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                    throw;
                }
            }

            public byte[] DecryptBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
            {
                if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));
                if (key.IsEmpty) throw new ArgumentException("Provided empty key", nameof(key));

                ReadOnlySpan<byte> iv = data.Slice(0, 24);
                ReadOnlySpan<byte> encryptedData = data[24..^64];
                ReadOnlySpan<byte> tag = data[^64..];

                byte[] decrypted = new byte[encryptedData.Length];
                byte[] calculatedTag = new byte[64];
                try
                {
                    calculatedTag = CalculateHMAC(key, iv, encryptedData);
                    if (!CryptographicOperations.FixedTimeEquals(tag, calculatedTag)) throw new VaultException(VaultException.ErrorContext.Decrypt, VaultException.ErrorReason.WrongHMAC);
                    var cipher = new XSalsa20Engine();
                    var parameters = new ParametersWithIV(new KeyParameter(key), iv);
                    cipher.Init(false, parameters);
                    cipher.ProcessBytes(encryptedData, decrypted);
                    return decrypted;
                }
                catch (Exception)
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(calculatedTag);
                }
            }
        }


        public interface IEncryptionAlgorithmProvider
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
                if (keySize is not (16 or 24 or 32)) throw new ArgumentOutOfRangeException(nameof(keySize));

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
                if (keySize is not (16 or 24 or 32)) throw new ArgumentOutOfRangeException(nameof(keySize));

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
                if (keySize is not (32 or 64 or 128)) throw new ArgumentOutOfRangeException(nameof(keySize));

                KeySize = keySize;
                EncryptionAlgorithm = algorithm;
            }
        }

        private class SerpentProvider : IEncryptionAlgorithmProvider
        {
            public byte KeySize { get; }

            public IEncryptionAlgorithm EncryptionAlgorithm { get; }

            internal SerpentProvider(byte keySize, SerpentAlgorithm algorithm)
            {
                ArgumentNullException.ThrowIfNull(keySize);
                ArgumentNullException.ThrowIfNull(algorithm);
                if (keySize is not (16 or 24 or 32)) throw new ArgumentOutOfRangeException(nameof(keySize));

                KeySize = keySize;
                EncryptionAlgorithm = algorithm;
            }
        }

        private class CameliaProvider : IEncryptionAlgorithmProvider
        {
            public byte KeySize { get; }

            public IEncryptionAlgorithm EncryptionAlgorithm { get; }

            internal CameliaProvider(byte keySize, CameliaAlgorithm algorithm)
            {
                ArgumentNullException.ThrowIfNull(keySize);
                ArgumentNullException.ThrowIfNull(algorithm);
                if (keySize is not (16 or 24 or 32)) throw new ArgumentOutOfRangeException(nameof(keySize));

                KeySize = keySize;
                EncryptionAlgorithm = algorithm;
            }
        }

        private class XSalsa20Provider : IEncryptionAlgorithmProvider
        {
            public byte KeySize { get; }

            public IEncryptionAlgorithm EncryptionAlgorithm { get; }

            internal XSalsa20Provider(byte keySize, XSalsa20Algorithm algorithm)
            {
                ArgumentNullException.ThrowIfNull(keySize);
                ArgumentNullException.ThrowIfNull(algorithm);
                if (keySize is not 32) throw new ArgumentOutOfRangeException(nameof(keySize));

                KeySize = keySize;
                EncryptionAlgorithm = algorithm;
            }
        }
    }
}
