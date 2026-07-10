using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class SecureBufferTests
    {
        public static TheoryData<int> ExpectedValidMemorySizes = new TheoryData<int>()
        {
            1,
            2,
            1_048_574,
            1_048_575,
            1_048_576, //1MB, from this point (inclusive) it should default to SecureLargeBuffer
            1_048_577
        };

        [Theory]
        [MemberData(nameof(ExpectedValidMemorySizes))]
        internal void CreateSetsCorrectLength(int expectedMemorySize)
        {
            ISecureBuffer buffer = SecureBuffer.Create(expectedMemorySize);
            //SecureKeyBuffer memory gets allocated in blocks defined by OS page size, we can't force exact size unless it aligns perfectly with page size
            //Because of that we know that if we ask for X bytes we will get a memory region that contains X bytes or more
            Assert.True(buffer.Length >= expectedMemorySize);

            buffer.Dispose();
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        internal void CreateThrowsForInvalidLength(int length)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => SecureBuffer.Create(length));
        }

        [Theory]
        [MemberData(nameof(ExpectedValidMemorySizes))]
        internal void CreateSetsCorrectSpanLength(int expectedMemorySize)
        {
            ISecureBuffer buffer = SecureBuffer.Create(expectedMemorySize);
            Assert.Equal(expectedMemorySize, buffer.AsSpan.Length);

            buffer.Dispose();
        }

        [Theory]
        [MemberData(nameof(ExpectedValidMemorySizes))]
        internal void CreateSetsCorrectMemoryLength(int expectedMemorySize)
        {
            ISecureBuffer buffer = SecureBuffer.Create(expectedMemorySize);
            Assert.Equal(expectedMemorySize, buffer.AsMemory.Length);

            buffer.Dispose();
        }

        [Theory]
        [MemberData(nameof(ExpectedValidMemorySizes))]
        internal void CreateAllocatesZeroedMemory(int expectedMemorySize)
        {
            ISecureBuffer buffer = SecureBuffer.Create(expectedMemorySize);
            Assert.True(buffer.AsSpan.IndexOfAnyExcept((byte)0) == -1);
        }

        [Fact]
        internal void StringToSecureBufferReturnsCorrectString()
        {
            string expected = "Password";
            ISecureBuffer? buffer = null;
            try
            {
                buffer = SecureBuffer.StringToSecureBuffer(expected);
                string actual = Encoding.Unicode.GetString(buffer.AsSpan);
                Assert.Equal(expected, actual);
            }
            finally
            {
                buffer?.Dispose();
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidStrings), MemberType = typeof(TestsHelper))]
        internal void StringToSecureBufferThrowsForInvalidStrings(string invalid, Type expectedException)
        {
            Assert.Throws(expectedException, () => SecureBuffer.StringToSecureBuffer(invalid));
        }
    }
}
