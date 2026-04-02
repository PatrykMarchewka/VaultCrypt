using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class PasswordHelperTests
    {
        byte[] password;
        byte[] salt;
        public PasswordHelperTests()
        {
            password = new byte[3] { 0, 1, 2 };
            salt = PasswordHelper.GenerateRandomSalt(32);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(ushort.MaxValue)]
        void GenerateRandomSaltReturnsCorrectLength(ushort length)
        {
            var salt = PasswordHelper.GenerateRandomSalt(length);

            Assert.Equal(length, salt.Length);
        }

        [Fact]
        void GenerateRandomSaltReturnsNonZeroedArray()
        {
            var salt = PasswordHelper.GenerateRandomSalt(10);

            Assert.False(new byte[10].SequenceEqual(salt));
        }

        [Fact]
        void GenerateRandomSaltReturnsDifferentValues()
        {
            var salt = PasswordHelper.GenerateRandomSalt(10);
            var salt2 = PasswordHelper.GenerateRandomSalt(10);

            Assert.False(salt.SequenceEqual(salt2));
        }

        [Fact]
        void DeriveKeyOutputsSameKeyForSameInput()
        {
            Span<byte> key = stackalloc byte[PasswordHelper.KeySize];
            Span<byte> key2 = stackalloc byte[PasswordHelper.KeySize];
            PasswordHelper.DeriveKey(password, salt, 1, key);
            PasswordHelper.DeriveKey(password, salt, 1, key2);

            Assert.True(key.SequenceEqual(key2));
        }

        [Fact]
        void DeriveKeyThrowsForTooSmallSpanSize()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => {
                Span<byte> key = stackalloc byte[PasswordHelper.KeySize - 1];
                PasswordHelper.DeriveKey(password, salt, 1, key);
            });
        }

        [Fact]
        void SecureStringToBytesReturnsCorrectString()
        {
            SecureString secureString = new SecureString();
            secureString.AppendChar('h');
            secureString.AppendChar('e');
            secureString.AppendChar('l');
            secureString.AppendChar('l');
            secureString.AppendChar('o');

            string hello = "hello";

            var bytes = PasswordHelper.SecureStringToBytes(secureString);
            //SecureString uses Unicode (UTF-16) encoding
            string bytesToString = Encoding.Unicode.GetString(bytes);

            Assert.Equal(hello, bytesToString);
        }
    }
}
