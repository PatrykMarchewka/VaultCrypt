using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Windows.Markup;

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

    public abstract class EncryptionAlgorithmTests<TSelf> where TSelf : EncryptionAlgorithmTests<TSelf>, new()
    {
        byte[] _key = RandomNumberGenerator.GetBytes(128);
        byte[] _data1 = RandomNumberGenerator.GetBytes(128);
        byte[] _data2 = RandomNumberGenerator.GetBytes(128);

        

        byte[] FlipSingleBit(byte[] data, int positionToFlip)
        {
            byte[] flipped = data;
            flipped[positionToFlip] ^= 1 << 3;
            return flipped;
        }

        #region Shared tests
        [Fact]
        void CalculateHMAC_SameOutput()
        {
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1, this._data2);
            byte[] result2 = EncryptionAlgorithm.CalculateHMAC(this._key.AsSpan(), this._data1.AsSpan(), this._data2.AsSpan());

            Assert.Equal(result1, result2);
        }

        [Fact]
        void CalculateHMAC_SameDataSameOutput()
        {
            byte[] concat = new byte[this._data1.Length + this._data2.Length];
            Buffer.BlockCopy(this._data1, 0, concat, 0, this._data1.Length);
            Buffer.BlockCopy(this._data2, 0, concat, this._data1.Length, this._data2.Length);
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, concat);
            byte[] result2 = EncryptionAlgorithm.CalculateHMAC(this._key.AsSpan(), this._data1.AsSpan(), this._data2.AsSpan());

            Assert.Equal(result1, result2);
        }

        void CalculateHMAC_CorrectSize()
        {
            byte[] result = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1);

            Assert.Equal(64, result.Length);
        }

        void CalculateHMAC_NotEmpty()
        {
            byte[] empty = new byte[64];
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1);

            Assert.NotEqual(empty, result1);
        }

        [Fact]
        void CalculateHMAC_DifferentOutput_DifferentKey()
        {
            byte[] newKey = new byte[] { 0, 1, 2 };
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1);
            byte[] result2 = EncryptionAlgorithm.CalculateHMAC(newKey, this._data1);

            Assert.NotEqual(result1, result2);
        }

        [Fact]
        void CalculateHMAC_DifferentOutput_DifferentData()
        {
            byte[] newData = new byte[] { 0, 1, 2 };
            byte[] result1 = EncryptionAlgorithm.CalculateHMAC(this._key, this._data1);
            byte[] result2 = EncryptionAlgorithm.CalculateHMAC(this._key, newData);

            Assert.NotEqual(result1, result2);
        }

        [Fact]
        void EncryptionAlgorithm_UniqueID()
        {
            var ids = EncryptionAlgorithm.GetEncryptionAlgorithmInfo.Keys.ToList();
            Assert.Equal(ids.Count, ids.Distinct().Count());
        }

        [Fact]
        void EncryptionAlgorithm_UniqueNames()
        {
            var names = EncryptionAlgorithm.GetEncryptionAlgorithmInfo.Values.Select(v => v.Name).ToList();
            Assert.Equal(names.Count, names.Distinct().Count());
        }

        [Theory]
        [InlineData(0, 16)]  // AES-128-GCM
        [InlineData(1, 24)]  // AES-192-GCM
        [InlineData(2, 32)]  // AES-256-GCM
        [InlineData(3, 16)]  // AES-128-CCM
        [InlineData(4, 24)]  // AES-192-CCM
        [InlineData(5, 32)]  // AES-256-CCM
        [InlineData(6, 32)]  // ChaCha20-Poly1305
        [InlineData(7, 16)]  // AES-128-EAX
        [InlineData(8, 24)]  // AES-192-EAX
        [InlineData(9, 32)]  // AES-256-EAX
        [InlineData(10, 16)]  // Twofish-128-CTR
        [InlineData(11, 24)]  // Twofish-192-CTR
        [InlineData(12, 32)]  // Twofish-256-CTR
        [InlineData(13, 32)]  // Threefish-256
        [InlineData(14, 64)]  // Threefish-512
        [InlineData(15, 128)] // Threefish-1024
        [InlineData(16, 16)]  // Serpent-128-GCM
        [InlineData(17, 24)]  // Serpent-192-GCM
        [InlineData(18, 32)]  // Serpent-256-GCM
        [InlineData(19, 16)]  // Serpent-128-CTR
        [InlineData(20, 24)]  // Serpent-192-CTR
        [InlineData(21, 32)]  // Serpent-256-CTR
        [InlineData(22, 16)]  // Camelia-128-GCM
        [InlineData(23, 24)]  // Camelia-192-GCM
        [InlineData(24, 32)]  // Camelia-256-GCM
        [InlineData(25, 16)]  // Camelia-128-OCB
        [InlineData(26, 24)]  // Camelia-192-OCB
        [InlineData(27, 32)]  // Camelia-256-OCB
        [InlineData(28, 16)]  // Camelia-128-CTR
        [InlineData(29, 24)]  // Camelia-192-CTR
        [InlineData(30, 32)]  // Camelia-256-CTR
        [InlineData(31, 32)]  // XSalsa20
        void Provider_CorrectKeySize(byte id, byte expectedKeySize)
        {
            byte actual = EncryptionAlgorithm.GetEncryptionAlgorithmInfo[id].Provider().KeySize;
            Assert.Equal(expectedKeySize, actual);
        }

        // 28bytes (12 IV + 16 tag)
        [Theory]
        [InlineData(0)]  // AES-128-GCM
        [InlineData(1)]  // AES-192-GCM
        [InlineData(2)]  // AES-256-GCM
        [InlineData(3)]  // AES-128-CCM
        [InlineData(4)]  // AES-192-CCM
        [InlineData(5)]  // AES-256-CCM
        [InlineData(6)]  // ChaCha20-Poly1305
        [InlineData(7)]  // AES-128-EAX
        [InlineData(8)]  // AES-192-EAX
        [InlineData(9)]  // AES-256-EAX
        [InlineData(16)] // Serpent-128-GCM
        [InlineData(17)] // Serpent-192-GCM
        [InlineData(18)] // Serpent-256-GCM
        [InlineData(22)] // Camelia-128-GCM
        [InlineData(23)] // Camelia-192-GCM
        [InlineData(24)] // Camelia-256-GCM
        [InlineData(25)] // Camelia-128-OCB
        [InlineData(26)] // Camelia-192-OCB
        [InlineData(27)] // Camelia-256-OCB
        void ExtraDataSize_Is28ForAeadModes(byte id)
        {
            Assert.Equal(28, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[id].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize);
        }

        // 76 bytes (12 IV + 64 tag)
        [Theory]
        [InlineData(10)] // Twofish-128-CTR
        [InlineData(11)] // Twofish-192-CTR
        [InlineData(12)] // Twofish-256-CTR
        [InlineData(13)] // Threefish-256-CTR
        [InlineData(14)] // Threefish-512-CTR
        [InlineData(15)] // Threefish-1024-CTR
        [InlineData(19)] // Serpent-128-CTR
        [InlineData(20)] // Serpent-192-CTR
        [InlineData(21)] // Serpent-256-CTR
        [InlineData(28)] // Camelia-128-CTR
        [InlineData(29)] // Camelia-192-CTR
        [InlineData(30)] // Camelia-256-CTR
        void ExtraDataSize_Is76ForCtrModes(byte id)
        {
            Assert.Equal(76, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[id].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize);
        }

        // 88 bytes (24 IV + 64 tag)
        [Theory]
        [InlineData(31)]
        void ExtraDataSize_Is88ForXSalsa20(byte id)
        {
            Assert.Equal(88, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[id].Provider().EncryptionAlgorithm.ExtraEncryptionDataSize);
        }
        #endregion


        public abstract IEnumerable<object[]> _providers { get; }
        public static IEnumerable<object[]> Providers => new TSelf()._providers;

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
            byte[] encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);

            Assert.Equal(_data1.Length + extraData, encrypted.Length);
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void EncryptionProducesRandomIV(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            byte[] iv = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key)[..12];
            byte[] iv2 = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key)[..12];

            Assert.NotEqual(iv, iv2);
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void EncryptProducesDifferentOutputData(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            byte[] outputdata = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key)[Provider.EncryptionAlgorithm.ExtraEncryptionDataSize..];
            byte[] outputdata2 = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key)[Provider.EncryptionAlgorithm.ExtraEncryptionDataSize..];

            Assert.NotEqual(outputdata, outputdata2);
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void DecryptThrowsForWrongKey(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            byte[] encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);
            byte[] newKey = FlipSingleBit(Key, 1);

            Assert.Throws(ExpectedMismatchedTagException, () => Provider.EncryptionAlgorithm.DecryptBytes(encrypted, newKey));
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void DecryptThrowsForTamperedIV(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            byte[] encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);
            byte[] encryptedTamperedIV = FlipSingleBit(encrypted, 0);

            Assert.Throws(ExpectedMismatchedTagException, () => Provider.EncryptionAlgorithm.DecryptBytes(encryptedTamperedIV, Key));

        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void DecryptThrowsForTamperedData(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            byte[] encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);
            byte[] encryptedTamperedData = FlipSingleBit(encrypted, Provider.EncryptionAlgorithm.ExtraEncryptionDataSize);

            Assert.Throws(ExpectedMismatchedTagException, () => Provider.EncryptionAlgorithm.DecryptBytes(encryptedTamperedData, Key));
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void DecryptThrowsForTamperedTag(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            byte[] encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);
            byte[] encryptedTamperedTag = null!;
            if (Provider.EncryptionAlgorithm.EncryptedOutputOrder == EncryptionAlgorithm.EncryptedOutputOrder.IV_Data_Tag)
            {
                encryptedTamperedTag = FlipSingleBit(encrypted, encrypted.Length - 1);
            }
            else if (Provider.EncryptionAlgorithm.EncryptedOutputOrder == EncryptionAlgorithm.EncryptedOutputOrder.IV_Tag_Data)
            {
                encryptedTamperedTag = FlipSingleBit(encrypted, Provider.EncryptionAlgorithm.ExtraEncryptionDataSize - 1);
            }

            Assert.Throws(ExpectedMismatchedTagException, () => Provider.EncryptionAlgorithm.DecryptBytes(encryptedTamperedTag, Key));
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void EncryptsAndDecryptsCorrectly(EncryptionAlgorithm.IEncryptionAlgorithmProvider Provider)
        {
            byte[] Key = _key.AsSpan().Slice(0, Provider.KeySize).ToArray();
            byte[] encrypted = Provider.EncryptionAlgorithm.EncryptBytes(_data1, Key);
            byte[] decrypted = Provider.EncryptionAlgorithm.DecryptBytes(encrypted, Key);

            Assert.Equal(_data1, decrypted);
        }
    }
    #region AES
    public class AESGCMAlgorithmTests : EncryptionAlgorithmTests<AESGCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Authentication 16 bytes][Data]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES192GCM.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(AuthenticationTagMismatchException);
    }

    public class AESCCMAlgorithmTests : EncryptionAlgorithmTests<AESCCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Authentication 16 bytes][Data]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128CCM.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES192CCM.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256CCM.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(AuthenticationTagMismatchException);
    }

    public class AESEAXAlgorithmTests : EncryptionAlgorithmTests<AESCCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Authentication 16 bytes][Data]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128EAX.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES192EAX.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256EAX.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(AuthenticationTagMismatchException);
    }
    #endregion

    #region ChaCha20
    public class ChaCha20Poly1305AlgorithmTests : EncryptionAlgorithmTests<ChaCha20Poly1305AlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Authentication 16 bytes][Data]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.ChaCha20Poly1305.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(AuthenticationTagMismatchException);
    }
    #endregion

    #region Twofish
    public class TwofishCTRAlgorithmTests : EncryptionAlgorithmTests<TwofishCTRAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 64 bytes]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Twofish128CTR.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Twofish192CTR.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Twofish256CTR.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultException);

    }
    #endregion

    #region Threefish
    public class ThreefishCTRAlgorithmTests : EncryptionAlgorithmTests<ThreefishCTRAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 64 bytes]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Threefish256CTR.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Threefish512CTR.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Threefish1024CTR.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultException);
    }
    #endregion

    #region Serpent
    public class SerpentGCMAlgorithmTests : EncryptionAlgorithmTests<SerpentGCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 16 bytes]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent128GCM.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent192GCM.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent256GCM.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(Org.BouncyCastle.Crypto.InvalidCipherTextException);
    }

    public class SerpentCTRAlgorithmTests : EncryptionAlgorithmTests<SerpentCTRAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 64 bytes]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent128CTR.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent192CTR.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent256CTR.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultException);
    }
    #endregion

    #region Camelia
    public class CameliaGCMAlgorithmTests : EncryptionAlgorithmTests<CameliaGCMAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 16 bytes]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia128GCM.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia192GCM.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia256GCM.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(Org.BouncyCastle.Crypto.InvalidCipherTextException);
    }

    public class CameliaOCBAlgoritmTests : EncryptionAlgorithmTests<CameliaOCBAlgoritmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 16 bytes]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia128OCB.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia192OCB.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia256OCB.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(Org.BouncyCastle.Crypto.InvalidCipherTextException);
    }

    public class CameliaCTRAlgorithmTests : EncryptionAlgorithmTests<CameliaCTRAlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 12 bytes][Data][Authentication 64 bytes]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia128CTR.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia192CTR.Provider()},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia256CTR.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultException);
    }
    #endregion

    #region XSalsa20
    public class XSalsa20AlgorithmTests : EncryptionAlgorithmTests<XSalsa20AlgorithmTests>, IEncryptionAlgorithmTests
    {
        //[IV 24 bytes][Data][Authentication 64 bytes]
        public override IEnumerable<object[]> _providers => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.XSalsa20.Provider()}
        };

        public override Type _expectedMismatchedTagException => typeof(VaultCrypt.Exceptions.VaultException);
    }
    #endregion
}
