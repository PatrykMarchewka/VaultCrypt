using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class SecureBufferReadWriteTests
    {
        public class SecureBufferReaderTests
        {
            [Fact]
            internal void SecureBufferReaderThrowsForInvalidData()
            {
                Assert.Throws<ArgumentNullException>(() => new SecureBufferReadWrite.SecureBufferReader(null!));
            }

            [Fact]
            internal void ReadByteReadsCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(1))
                {
                    buffer.AsSpan[0] = byte.MaxValue;

                    SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                    byte actual = reader.ReadByte();
                    Assert.Equal(buffer.AsSpan[0], actual);
                }
            }

            [Fact]
            internal void ReadByteThrowsForTryingToReadOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                Assert.Throws<InvalidOperationException>(() => reader.ReadByte());
            }

            [Fact]
            internal void ReadBytesReadsCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(10))
                {
                    buffer.AsSpan[0] = 0;
                    buffer.AsSpan[1] = 1;
                    buffer.AsSpan[2] = 2;
                    buffer.AsSpan[3] = 3;

                    SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                    using (ISecureBuffer firstHalf = reader.ReadBytes(2))
                    {
                        Assert.True(firstHalf.AsSpan.SequenceEqual(buffer.AsSpan.Slice(0, 2)));
                    }

                    using (ISecureBuffer secondHalf = reader.ReadBytes(2))
                    {
                        Assert.True(secondHalf.AsSpan.SequenceEqual(buffer.AsSpan.Slice(2, 2)));
                    }
                }
            }

            [Theory]
            [InlineData(int.MinValue)]
            [InlineData(-1)]
            [InlineData(0)]
            [InlineData(int.MaxValue)]
            internal void ReadBytesThrowsForInvalidLength(int length)
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                Assert.Throws<ArgumentOutOfRangeException>(() => reader.ReadBytes(length));
            }

            [Fact]
            internal void ReadUInt16ReadsCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(2))
                {
                    buffer.AsSpan[0] = byte.MaxValue;
                    buffer.AsSpan[1] = byte.MaxValue;

                    SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                    ushort actual = reader.ReadUInt16();

                    Assert.Equal(ushort.MaxValue, actual);
                }
            }

            [Fact]
            internal void ReadUInt16ThrowsForTryingToReadOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                Assert.Throws<InvalidOperationException>(() => reader.ReadUInt16());
            }

            [Fact]
            internal void ReadUInt32ReadsCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(4))
                {
                    buffer.AsSpan[0] = byte.MaxValue;
                    buffer.AsSpan[1] = byte.MaxValue;
                    buffer.AsSpan[2] = byte.MaxValue;
                    buffer.AsSpan[3] = byte.MaxValue;

                    SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                    uint actual = reader.ReadUInt32();

                    Assert.Equal(uint.MaxValue, actual);
                }
            }

            [Fact]
            internal void ReadUInt32ThrowsForTryingToReadOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                Assert.Throws<InvalidOperationException>(() => reader.ReadUInt32());
            }

            [Fact]
            internal void ReadUInt64ReadsCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(8))
                {
                    buffer.AsSpan[0] = byte.MaxValue;
                    buffer.AsSpan[1] = byte.MaxValue;
                    buffer.AsSpan[2] = byte.MaxValue;
                    buffer.AsSpan[3] = byte.MaxValue;
                    buffer.AsSpan[4] = byte.MaxValue;
                    buffer.AsSpan[5] = byte.MaxValue;
                    buffer.AsSpan[6] = byte.MaxValue;
                    buffer.AsSpan[7] = byte.MaxValue;

                    SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                    ulong actual = reader.ReadUInt64();

                    Assert.Equal(ulong.MaxValue, actual);
                }
            }

            [Fact]
            internal void ReadUInt64ThrowsForTryingToReadOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                Assert.Throws<InvalidOperationException>(() => reader.ReadUInt64());
            }

            [Fact]
            internal void ReadInt64ReadsCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(8))
                {
                    buffer.AsSpan[0] = byte.MaxValue;
                    buffer.AsSpan[1] = byte.MaxValue;
                    buffer.AsSpan[2] = byte.MaxValue;
                    buffer.AsSpan[3] = byte.MaxValue;
                    buffer.AsSpan[4] = byte.MaxValue;
                    buffer.AsSpan[5] = byte.MaxValue;
                    buffer.AsSpan[6] = byte.MaxValue;
                    buffer.AsSpan[7] = 127;

                    SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                    long actual = reader.ReadInt64();

                    Assert.Equal(long.MaxValue, actual);
                }
            }

            [Fact]
            internal void ReadInt64ThrowsForTryingToReadOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                Assert.Throws<InvalidOperationException>(() => reader.ReadInt64());
            }

            [Fact]
            internal void AllReadersReadCorrectlyAndAdvanceIndex()
            {
                //Total length must be above 23 in order to test all methods (1 + 2 + 4 + 8 + 8 + >0)
                using (ISecureBuffer buffer = SecureBuffer.Create(25))
                {
                    for (int i = 0; i < buffer.AsSpan.Length; i++)
                    {
                        buffer.AsSpan[i] = byte.MaxValue;
                    }

                    SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(buffer);
                    byte actualByte = reader.ReadByte();
                    ushort actualUShort = reader.ReadUInt16();
                    uint actualUInt = reader.ReadUInt32();
                    ulong actualULong = reader.ReadUInt64();
                    long actualLong = reader.ReadInt64();
                    Assert.Equal(byte.MaxValue, actualByte);
                    Assert.Equal(ushort.MaxValue, actualUShort);
                    Assert.Equal(uint.MaxValue, actualUInt);
                    Assert.Equal(ulong.MaxValue, actualULong);
                    Assert.Equal(-1, actualLong);

                    using (ISecureBuffer actualBytes = reader.ReadBytes(2))
                    {
                        Span<byte> expected = buffer.AsSpan.Slice(23);
                        Assert.True(actualBytes.AsSpan.SequenceEqual(expected));
                    }
                }
            }
        }

        public class SecureBufferWriterTests
        {
            [Fact]
            internal void SpanWriterThrowsForInvalidData()
            {
                Assert.Throws<ArgumentNullException>(() => new SecureBufferReadWrite.SecureBufferWriter(null!));
            }

            [Fact]
            internal void WriteByteWritesCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(1))
                {
                    SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                    writer.WriteByte(byte.MaxValue);

                    Assert.Equal(byte.MaxValue, buffer.AsSpan[0]);
                }
            }

            [Fact]
            internal void WriteByteThrowsForTryingToWriteOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                Assert.Throws<InvalidOperationException>(() => writer.WriteByte(byte.MaxValue));
            }

            [Fact]
            internal void WriteSpanWritesCorrectlyAndAdvancesIndex()
            {
                byte[] expected = new byte[10];
                for (int i = 0; i < expected.Length; i++)
                {
                    expected[0] = byte.MaxValue;
                }

                using (ISecureBuffer buffer = SecureBuffer.Create(10))
                {
                    SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                    writer.WriteSpan(expected);

                    Assert.True(buffer.AsSpan.SequenceEqual(expected));
                }
            }

            [Fact]
            internal void WriteSpanThrowsForTryingToWriteOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                Assert.Throws<InvalidOperationException>(() => writer.WriteSpan(new byte[1]));
            }

            [Fact]
            internal void WriteUInt16WritesCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(2))
                {
                    SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                    writer.WriteUInt16(ushort.MaxValue);

                    for (int i = 0; i < buffer.AsSpan.Length; i++)
                    {
                        buffer.AsSpan[i] = byte.MaxValue;
                    }
                }
            }

            [Fact]
            internal void WriteUInt16ThrowsForTryingToWriteOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                Assert.Throws<InvalidOperationException>(() => writer.WriteUInt16(ushort.MaxValue));
            }

            [Fact]
            internal void WriteUInt32WritesCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(4))
                {
                    SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                    writer.WriteUInt32(uint.MaxValue);

                    for (int i = 0; i < buffer.AsSpan.Length; i++)
                    {
                        buffer.AsSpan[i] = byte.MaxValue;
                    }
                }
            }

            [Fact]
            internal void WriteUInt32ThrowsForTryingToWriteOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                Assert.Throws<InvalidOperationException>(() => writer.WriteUInt32(uint.MaxValue));
            }

            [Fact]
            internal void WriteUInt64WritesCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(8))
                {
                    SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                    writer.WriteUInt64(ulong.MaxValue);

                    for (int i = 0; i < buffer.AsSpan.Length; i++)
                    {
                        buffer.AsSpan[i] = byte.MaxValue;
                    }
                }
            }

            [Fact]
            internal void WriteUInt64ThrowsForTryingToWriteOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                Assert.Throws<InvalidOperationException>(() => writer.WriteUInt64(ulong.MaxValue));
            }

            [Fact]
            internal void WriteInt64WritesCorrectlyAndAdvancesIndex()
            {
                using (ISecureBuffer buffer = SecureBuffer.Create(8))
                {
                    SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                    writer.WriteInt64(long.MaxValue);

                    for (int i = 0; i < buffer.AsSpan.Length; i++)
                    {
                        buffer.AsSpan[i] = byte.MaxValue;
                    }
                }
            }

            [Fact]
            internal void WriteInt64ThrowsForTryingToWriteOutsideData()
            {
                ISecureBuffer buffer = TestsHelper.EmptySecureBuffer;
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                Assert.Throws<InvalidOperationException>(() => writer.WriteInt64(long.MaxValue));
            }

            [Fact]
            internal void AllWritersWriteCorrectlyAndAdvanceIndex()
            {
                byte[] expectedSmallSpan = new byte[10] { 148, 2, 160, 228, 25, 108, 7, 15, 127, 6 };
                byte[] expectedSpan = new byte[33] { 1, 10, 0, 100, 0, 0, 0, 232, 3, 0, 0, 0, 0, 0, 0, 16, 39, 0, 0, 0, 0, 0, 0, 148, 2, 160, 228, 25, 108, 7, 15, 127, 6 };

                using (ISecureBuffer buffer = SecureBuffer.Create(33))
                {
                    SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(buffer);
                    writer.WriteByte(1);
                    writer.WriteUInt16(10);
                    writer.WriteUInt32(100);
                    writer.WriteUInt64(1000);
                    writer.WriteInt64(10000);
                    writer.WriteSpan(expectedSmallSpan);

                    Assert.True(buffer.AsSpan.SequenceEqual(expectedSpan));
                }
            }
        }
    }
}
