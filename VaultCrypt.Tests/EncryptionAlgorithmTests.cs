using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    interface IEncryptionAlgorithmTests
    {
        public void ThrowsForEmptyKey(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);
        public void ThrowsForEmptyData(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);
        public void CorrectExtraEncryptionDataSize(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);
        public void EncryptionProducesRandomIV(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);
        public void EncryptProducesDifferentOutputData(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);
        public void DecryptThrowsForWrongKey(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);
        public void DecryptThrowsForTamperedIV(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);
        public void DecryptThrowsForTamperedTag(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);
        public void DecryptThrowsForTamperedData(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);
        public void EncryptsAndDecryptsCorrectly(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider);

    }

    public class EncryptionAlgorithmSharedTests()
    {
        byte[] _key = RandomNumberGenerator.GetBytes(PasswordHelper.KeySize);
        byte[] _data1 = RandomNumberGenerator.GetBytes(128);
        byte[] _data2 = RandomNumberGenerator.GetBytes(128);


        [Fact]
        internal void CalculateHMAC_SameOutput()
        {
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1, this._data2);
            byte[] result2 = EncryptionAlgorithm.CalculateHMAC(this._key.AsSpan(), this._data1.AsSpan(), this._data2.AsSpan());

            Assert.Equal(result1, result2);
        }

        [Fact]
        internal void CalculateHMAC_SameDataSameOutput()
        {
            byte[] concat = new byte[this._data1.Length + this._data2.Length];
            Buffer.BlockCopy(this._data1, 0, concat, 0, this._data1.Length);
            Buffer.BlockCopy(this._data2, 0, concat, this._data1.Length, this._data2.Length);
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, concat);
            byte[] result2 = EncryptionAlgorithm.CalculateHMAC(this._key.AsSpan(), this._data1.AsSpan(), this._data2.AsSpan());

            Assert.Equal(result1, result2);
        }

        [Fact]
        internal void CalculateHMAC_CorrectSize()
        {
            byte[] result = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1);

            Assert.Equal(64, result.Length);
        }

        [Fact]
        internal void CalculateHMAC_NotEmpty()
        {
            byte[] empty = new byte[64];
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1);

            Assert.NotEqual(empty, result1);
        }

        [Fact]
        internal void CalculateHMAC_DifferentOutput_DifferentKey()
        {
            byte[] newKey = new byte[] { 0, 1, 2 };
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1);
            byte[] result2 = EncryptionAlgorithm.CalculateHMAC(newKey, this._data1);

            Assert.NotEqual(result1, result2);
        }

        [Fact]
        internal void CalculateHMAC_DifferentOutput_DifferentData()
        {
            byte[] newData = new byte[] { 0, 1, 2 };
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1);
            byte[] result2 = EncryptionAlgorithm.CalculateHMAC(this._key, newData);

            Assert.NotEqual(result1, result2);
        }

        [Fact]
        internal void EncryptionAlgorithm_UniqueNames()
        {
            var names = EncryptionAlgorithm.GetEncryptionAlgorithmInfo.Values.Select(v => v.Name).ToList();
            Assert.Equal(names.Count, names.Distinct().Count());
        }
    }

    public abstract class EncryptionAlgorithmTests<TSelf> where TSelf : EncryptionAlgorithmTests<TSelf>, new()
    {
        byte[] _key = RandomNumberGenerator.GetBytes(PasswordHelper.KeySize);
        byte[] _data1 = RandomNumberGenerator.GetBytes(128);

        byte[] FlipSingleBit(ReadOnlySpan<byte> data, int positionToFlip)
        {
            byte[] flipped = data.ToArray();
            flipped[positionToFlip] ^= 1 << 3;
            return flipped;
        }


        public abstract TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers { get; }
        public static TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> Providers => new TSelf()._providers;

        public abstract Type _expectedMismatchedTagException { get; }
        public static Type ExpectedMismatchedTagException
        {
            get
            {
                var type = new TSelf()._expectedMismatchedTagException;
                if (!typeof(Exception).IsAssignableFrom(type)) throw new InvalidOperationException($"{type.FullName} must derive from System.Exception.");
                return type;
            }
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void ThrowsForEmptyKey(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            Assert.Throws<ArgumentException>(() => Provider.EncryptionAlgorithm.EncryptBytes(_data1, Array.Empty<byte>()));
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void ThrowsForEmptyData(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            Assert.Throws<ArgumentException>(() => Provider.EncryptionAlgorithm.EncryptBytes(Array.Empty<byte>(), Key));
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void CorrectExtraEncryptionDataSize(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            short extraData = Provider.EncryptionAlgorithm.ExtraEncryptionDataSize;
            using (ISecureBuffer encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key))
            {
                Assert.Equal(_data1.Length + extraData, encrypted.AsSpan.Length);
            }
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void EncryptionProducesRandomIV(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            ISecureBuffer iv = null!;
            ISecureBuffer iv2 = null!;
            try
            {
                iv = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);
                iv2 = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);

                byte[] ivBytes = iv.AsSpan[..12].ToArray();
                byte[] iv2Bytes = iv2.AsSpan[..12].ToArray();
                Assert.False(ivBytes.SequenceEqual(iv2Bytes));
            }
            finally
            {
                iv?.Dispose();
                iv2?.Dispose();
            }
            
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void EncryptProducesDifferentOutputData(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            ISecureBuffer outputData = null!;
            ISecureBuffer outputData2 = null!;
            try
            {
                outputData = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);
                outputData2 = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);
                Assert.False(outputData.AsSpan.Slice(Provider.EncryptionAlgorithm.ExtraEncryptionDataSize).SequenceEqual(outputData2.AsSpan.Slice(Provider.EncryptionAlgorithm.ExtraEncryptionDataSize)));
            }
            finally
            {
                outputData?.Dispose();
                outputData2?.Dispose();
            }
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void DecryptThrowsForWrongKey(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            using (ISecureBuffer encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key))
            {
                byte[] newKey = FlipSingleBit(Key, 1);

                Assert.Throws(ExpectedMismatchedTagException, () => Provider.EncryptionAlgorithm.DecryptBytes(encrypted.AsSpan, newKey));
            }
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void DecryptThrowsForTamperedIV(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            using (ISecureBuffer encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key))
            {
                byte[] encryptedTamperedIV = FlipSingleBit(encrypted.AsSpan, 0);

                Assert.Throws(ExpectedMismatchedTagException, () => Provider.EncryptionAlgorithm.DecryptBytes(encryptedTamperedIV, Key));
            }

        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void DecryptThrowsForTamperedData(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            using (ISecureBuffer encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key))
            {
                byte[] encryptedTamperedData = FlipSingleBit(encrypted.AsSpan, Provider.EncryptionAlgorithm.ExtraEncryptionDataSize);

                Assert.Throws(ExpectedMismatchedTagException, () => Provider.EncryptionAlgorithm.DecryptBytes(encryptedTamperedData, Key));
            }
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void DecryptThrowsForTamperedTag(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            using (ISecureBuffer encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key))
            {
                byte[] encryptedTamperedTag = null!;
                if (Provider.EncryptionAlgorithm.EncryptedOutputOrder == EncryptionAlgorithm.EncryptedOutputOrder.IV_Data_Tag)
                {
                    encryptedTamperedTag = FlipSingleBit(encrypted.AsSpan, encrypted.AsSpan.Length - 1);
                }
                else if (Provider.EncryptionAlgorithm.EncryptedOutputOrder == EncryptionAlgorithm.EncryptedOutputOrder.IV_Tag_Data)
                {
                    encryptedTamperedTag = FlipSingleBit(encrypted.AsSpan, Provider.EncryptionAlgorithm.ExtraEncryptionDataSize - 1);
                }

                Assert.Throws(ExpectedMismatchedTagException, () => Provider.EncryptionAlgorithm.DecryptBytes(encryptedTamperedTag, Key));
            }
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void EncryptsAndDecryptsCorrectly(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            ISecureBuffer encrypted = null!;
            ISecureBuffer decrypted = null!;
            try
            {
                encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);
                decrypted = Provider.EncryptionAlgorithm.DecryptBytes(encrypted.AsSpan, Key);
                Assert.True(decrypted.AsSpan.SequenceEqual(_data1));
            }
            finally
            {
                encrypted?.Dispose();
                decrypted?.Dispose();
            }
            
        }
    }
    #region AES
    public class AESGCMAlgorithmTests : EncryptionAlgorithmTests<AESGCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Authentication 16 bytes][Data]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            {EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM.Provider() },
            {EncryptionAlgorithm.EncryptionAlgorithmInfo.AES192GCM.Provider() },
            {EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.Provider() }
        };

        public override Type _expectedMismatchedTagException => typeof(AuthenticationTagMismatchException);
    }

    public class AESCCMAlgorithmTests : EncryptionAlgorithmTests<AESCCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Authentication 16 bytes][Data]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            {EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128CCM.Provider() },
            {EncryptionAlgorithm.EncryptionAlgorithmInfo.AES192CCM.Provider() },
            {EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256CCM.Provider() }
        };

        public override Type _expectedMismatchedTagException => typeof(AuthenticationTagMismatchException);
    }

    public class AESEAXAlgorithmTests : EncryptionAlgorithmTests<AESCCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Authentication 16 bytes][Data]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            {EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128EAX.Provider() },
            {EncryptionAlgorithm.EncryptionAlgorithmInfo.AES192EAX.Provider() },
            {EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256EAX.Provider() }
        };

        public override Type _expectedMismatchedTagException => typeof(AuthenticationTagMismatchException);
    }
    #endregion

    #region ChaCha20
    public class ChaCha20Poly1305AlgorithmTests : EncryptionAlgorithmTests<ChaCha20Poly1305AlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Authentication 16 bytes][Data]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.ChaCha20Poly1305.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(AuthenticationTagMismatchException);
    }
    #endregion

    #region Twofish
    public class TwofishCTRAlgorithmTests : EncryptionAlgorithmTests<TwofishCTRAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 64 bytes]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Twofish128CTR.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Twofish192CTR.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Twofish256CTR.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultDecryptionException);

    }
    #endregion

    #region Threefish
    public class ThreefishCTRAlgorithmTests : EncryptionAlgorithmTests<ThreefishCTRAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 64 bytes]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Threefish256CTR.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Threefish512CTR.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Threefish1024CTR.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultDecryptionException);
    }
    #endregion

    #region Serpent
    public class SerpentGCMAlgorithmTests : EncryptionAlgorithmTests<SerpentGCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 16 bytes]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent128GCM.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent192GCM.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent256GCM.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(Org.BouncyCastle.Crypto.InvalidCipherTextException);
    }

    public class SerpentCTRAlgorithmTests : EncryptionAlgorithmTests<SerpentCTRAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 64 bytes]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent128CTR.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent192CTR.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent256CTR.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultDecryptionException);
    }
    #endregion

    #region Camelia
    public class CameliaGCMAlgorithmTests : EncryptionAlgorithmTests<CameliaGCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 16 bytes]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia128GCM.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia192GCM.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia256GCM.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(Org.BouncyCastle.Crypto.InvalidCipherTextException);
    }

    public class CameliaOCBAlgoritmTests : EncryptionAlgorithmTests<CameliaOCBAlgoritmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 16 bytes]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia128OCB.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia192OCB.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia256OCB.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(Org.BouncyCastle.Crypto.InvalidCipherTextException);
    }

    public class CameliaCTRAlgorithmTests : EncryptionAlgorithmTests<CameliaCTRAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 64 bytes]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia128CTR.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia192CTR.Provider()},
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia256CTR.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultDecryptionException);
    }
    #endregion

    #region XSalsa20
    public class XSalsa20AlgorithmTests : EncryptionAlgorithmTests<XSalsa20AlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 24 bytes][Data][Authentication 64 bytes]
        public override TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider> _providers => new TheoryData<EncryptionAlgorithm.IEncryptionAlgorithmProvider>()
        {
            { EncryptionAlgorithm.EncryptionAlgorithmInfo.XSalsa20.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultDecryptionException);
    }
    #endregion
}
