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
            void SecureLargeBufferSetsCorrectLength()
            {
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
                Assert.Equal(memory.AsSpan.Length, memory.Length);

                memory.Dispose();
            }

            [Fact]
            void SecureLargeBufferAllocatesCorrectSize()
            {
                int expectedSize = RandomNumberGenerator.GetInt32(1, 1000);
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: expectedSize);
                Assert.Equal(expectedSize, memory.Length);

                memory.Dispose();
            }

            [Fact]
            void SecureLargeBufferAllocatesZeroedMemory()
            {
                int randomLength = RandomNumberGenerator.GetInt32(1, 1000);
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(randomLength);
                Assert.True(memory.AsSpan.SequenceEqual(new byte[randomLength]));

                memory.Dispose();
            }

            [Fact]
            void SecureLargeBufferThrowsForZeroLength()
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer.SecureLargeBuffer(0));
            }

            [Fact]
            void SecureLargeBufferThrowsForNegativeLength()
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer.SecureLargeBuffer(-1));
            }

            [Fact]
            void AsSpanThrowsForDisposedValue()
            {
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.AsSpan; });
            }

            [Fact]
            void LengthThrowsForDisposedValue()
            {
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.Length; });
            }

            [Fact]
            void AsMemoryThrowsForDisposedValue()
            {
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.AsMemory; });
            }

            [Fact]
            unsafe void DisposeZeroesMemory()
            {
                int randomLength =  RandomNumberGenerator.GetInt32(1, 1000);
                SecureBuffer.SecureLargeBuffer memory = new SecureBuffer.SecureLargeBuffer(randomLength);
                //Fill memory buffer with random values
                for (int i = 0; i < randomLength; i++)
                {
                    memory.AsSpan[i] = (byte)RandomNumberGenerator.GetInt32(255);
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
            void SecureKeyBufferSetsCorrectLength()
            {
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
                Assert.Equal(memory.AsSpan.Length, memory.Length);

                memory.Dispose();
            }

            [Fact]
            void SecureKeyBufferAllocatesCorrectSize()
            {
                int expectedSize = RandomNumberGenerator.GetInt32(1, 10_000);
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: expectedSize);
                //Memory gets allocated in blocks defined by OS page size, because of that we can't force exact size just that it will create atleast x bytes
                Assert.True(expectedSize < memory.Length);

                memory.Dispose();
            }

            [Fact]
            void SecureKeyBufferAllocatesZeroedMemory()
            {
                int randomLength = RandomNumberGenerator.GetInt32(1, 10_000);
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(randomLength);
                Assert.True(memory.AsSpan.SequenceEqual(new byte[memory.Length]));

                memory.Dispose();
            }

            [Fact]
            void SecureKeyBufferThrowsForZeroLength()
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer.SecureKeyBuffer(0));
            }

            [Fact]
            void SecureKeyBufferThrowsForNegativeLength()
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer.SecureKeyBuffer(-1));
            }

            [Fact]
            void SecureKeyBufferThrowsForMassiveLength()
            {
                int tenMB = 10_485_760;
                Assert.Throws<SecurityException>(() => new SecureBuffer.SecureKeyBuffer(tenMB));
            }

            [Fact]
            void AsSpanProvidesCorrectSpan()
            {
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
            }

            [Fact]
            void AsSpanThrowsForDisposedValue()
            {
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.AsSpan; });
            }

            [Fact]
            void LengthThrowsForDisposedValue()
            {
                SecureBuffer.SecureKeyBuffer memory = new SecureBuffer.SecureKeyBuffer(length: RandomNumberGenerator.GetInt32(1, 1000));
                memory.Dispose();

                Assert.Throws<ObjectDisposedException>(() => { var test = memory.Length; });
            }
        }
    }
}
