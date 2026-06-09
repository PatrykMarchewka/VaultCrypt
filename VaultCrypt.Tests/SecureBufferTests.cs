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

        public class SecureLargeBufferTests
        {
            [Fact]
            internal void SecureLargeBufferSetsCorrectLength()
            {
                int expectedSize = 100;
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: expectedSize);
                Assert.Equal(expectedSize, memory.Length);

                memory.Dispose();
            }

            [Fact]
            internal void SecureLargeBufferAllocatesCorrectSize()
            {
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: 100);
                Assert.Equal(memory.AsSpan.Length, memory.Length);
                Assert.Equal(memory.AsMemory.Length, memory.Length);

                memory.Dispose();
            }

            [Fact]
            internal void SecureLargeBufferAllocatesZeroedMemory()
            {
                int randomLength = 100;
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(randomLength);
                Assert.True(memory.AsSpan.SequenceEqual(new byte[randomLength]));

                memory.Dispose();
            }

            [Theory]
            [InlineData(int.MinValue)]
            [InlineData(-1)]
            [InlineData(0)]
            internal void SecureLargeBufferThrowsForInvalidLength(int length)
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer.SecureLargeBuffer(length));
            }

            [Fact]
            internal void AsSpanThrowsForDisposedValue()
            {
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: 10);
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.AsSpan; });
            }

            [Fact]
            internal void LengthThrowsForDisposedValue()
            {
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: 10);
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.Length; });
            }

            [Fact]
            internal void AsMemoryThrowsForDisposedValue()
            {
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: 10);
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.AsMemory; });
            }

            [Fact]
            unsafe internal void DisposeZeroesMemory()
            {
                int randomLength =  100;
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(randomLength);
                //Fill memory buffer with random values
                for (int i = 0; i < randomLength; i++)
                {
                    memory.AsSpan[i] = (byte)Random.Shared.Next(255);
                }

                //Get pointer to memory that stays after Dispose gets called
                byte* pointer;
                fixed(byte* ptr = memory.AsSpan)
                {
                    pointer = ptr;
                }

                byte[] after = new byte[randomLength];

                memory.Dispose();
                //Copying into managed memory to prevent undefined behaviour from reading freed memory
                for (int i = 0; i < randomLength; i++)
                {
                    after[i] = pointer[i];
                }

                int zeroed = 0;
                int notZeroed = 0;
                for (int i = 0; i < randomLength; i++)
                {
                    if (after[i] == 0) zeroed++;
                    else notZeroed++;
                }

                //Because memory was freed we cannot guarantee it wont get instantly overwritten, because of that we check if atleast 95% of it has been it zeroed
                Assert.True((((float)zeroed / randomLength) * 100) > 95);
            }
        }

        public class SecureKeyBufferTests
        {
            [Fact]
            internal void SecureKeyBufferSetsCorrectLength()
            {
                int expectedSize = 100;
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: expectedSize);
                //Memory gets allocated in blocks defined by OS page size, because of that we can't force exact size unless it aligns perfectly
                //Because of that we know that if we ask for X bytes we will get a memory region that contains X bytes or more
                Assert.True(expectedSize <= memory.Length);

                memory.Dispose();
            }

            [Fact]
            internal void SecureKeyBufferAllocatesCorrectSize()
            {
                int expectedSize = 100;
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: expectedSize);
                Assert.Equal(expectedSize, memory.AsSpan.Length);

                memory.Dispose();
            }

            [Fact]
            internal void SecureKeyBufferPadsLengthToSystemPageSize()
            {
                int expectedSize = 100;
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: expectedSize);
                Assert.True(memory.Length % Environment.SystemPageSize == 0);

                memory.Dispose();
            }

            [Fact]
            internal void SecureKeyBufferDoesntOverAllocateForAlignedMemorySize()
            {
                int expectedSize = Environment.SystemPageSize;
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: expectedSize);
                //Asserting that perfectly aligned memory size allocates fully without forcing empty regions
                Assert.Equal(expectedSize, memory.Length);
                memory.Dispose();
            }

            [Fact]
            internal void SecureKeyBufferAllocatesZeroedMemory()
            {
                int randomLength = 100;
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(randomLength);
                Assert.True(memory.AsSpan.IndexOfAnyExcept((byte)0) == -1);

                memory.Dispose();
            }

            public static TheoryData<int, Type> InvalidLengthAndException = new TheoryData<int, Type>()
            {
                {int.MinValue, typeof(ArgumentOutOfRangeException) },
                {-1, typeof(ArgumentOutOfRangeException) },
                {0, typeof(ArgumentOutOfRangeException) },
                {10_485_760, typeof(SecurityException) }
            };

            [Theory]
            [MemberData(nameof(InvalidLengthAndException))]
            internal void SecureKeyBufferThrowsForInvalidLength(int length, Type exception)
            {
                Assert.Throws(exception, () => new SecureBuffer.SecureKeyBuffer(length));
            }

            [Fact]
            internal void AsSpanThrowsForDisposedValue()
            {
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.AsSpan; });
            }

            [Fact]
            internal void LengthThrowsForDisposedValue()
            {
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.Length; });
            }
        }
    }
}
