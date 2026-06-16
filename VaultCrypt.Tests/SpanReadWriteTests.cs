using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class SpanReadWriteTests
    {
        #region SpanReader
        [Fact]
        internal void SpanReaderThrowsForEmptyData()
        {
            Assert.Throws<ArgumentException>(() => new SpanReader(new byte[0]));
        }

        [Fact]
        internal void ReadByteReadsCorrectlyAndAdvancesIndex()
        {
            int size = 10;
            byte[] expected = new byte[size];
            Random.Shared.NextBytes(expected);
            SpanReader reader = new SpanReader(expected);
            for (int i = 0; i < size; i++)
            {
                Assert.Equal(expected[i], reader.ReadByte());
            }
        }

        [Fact]
        internal void ReadByteThrowsForTryingToReadOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanReader reader = new SpanReader(new byte[1]);
                reader.ReadByte();
                reader.ReadByte();
            });
        }

        [Fact]
        internal void ReadBytesReadsCorrectlyAndAdvancesIndex()
        {
            int size = 10;
            byte[] randomData = new byte[size];
            Random.Shared.NextBytes(randomData);
            SpanReader reader = new SpanReader(randomData);

            ReadOnlySpan<byte> firstHalf = randomData.AsSpan().Slice(0, 5);
            ReadOnlySpan<byte> secondHalf = randomData.AsSpan().Slice(5, 5);

            using ISecureBuffer actualFirstHalf = reader.ReadBytes(5);
            using ISecureBuffer actualSecondHalf = reader.ReadBytes(5);

            Assert.True(firstHalf.SequenceEqual(actualFirstHalf.AsSpan));
            Assert.True(secondHalf.SequenceEqual(actualSecondHalf.AsSpan));
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(int.MaxValue)]
        internal void ReadBytesThrowsForInvalidLength(int length)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                SpanReader reader = new SpanReader(new byte[1]);
                reader.ReadBytes(length);
            });
        }

        [Fact]
        internal void ReadUInt16ReadsCorrectlyAndAdvancesIndex()
        {
            int size = 10; //Must be divisible by two
            byte[] randomData = new byte[10];
            Random.Shared.NextBytes(randomData);
            SpanReader reader = new SpanReader(randomData);

            for (int i = 0; i < size - 2; i += 2)
            {
                ushort expected = BinaryPrimitives.ReadUInt16LittleEndian(randomData.AsSpan().Slice(i, 2));
                ushort actual = reader.ReadUInt16();
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        internal void ReadUInt16ThrowsForTryingToReadOutsideData()
        {
            byte[] randomData = new byte[1];
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanReader reader = new SpanReader(randomData);
                reader.ReadUInt16();
            });
        }

        [Fact]
        internal void ReadUInt32ReadsCorrectlyAndAdvancesIndex()
        {
            int size = 20; //Must be divisible by four
            byte[] randomData = new byte[size];
            Random.Shared.NextBytes(randomData);
            SpanReader reader = new SpanReader(randomData);

            for (int i = 0; i < size - 4; i += 4)
            {
                uint expected = BinaryPrimitives.ReadUInt32LittleEndian(randomData.AsSpan().Slice(i, 4));
                uint actual = reader.ReadUInt32();
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        internal void ReadUInt32ThrowsForTryingToReadOutsideData()
        {
            byte[] randomData = new byte[1];
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanReader reader = new SpanReader(randomData);
                reader.ReadUInt32();
            });
        }

        [Fact]
        internal void ReadUInt64ReadsCorrectlyAndAdvancesIndex()
        {
            int size = 40; //Must be divisible by eight
            byte[] randomData = new byte[40];
            Random.Shared.NextBytes(randomData);
            SpanReader reader = new SpanReader(randomData);

            for (int i = 0; i < size - 8; i += 8)
            {
                ulong expected = BinaryPrimitives.ReadUInt64LittleEndian(randomData.AsSpan().Slice(i, 8));
                ulong actual = reader.ReadUInt64();
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        internal void ReadUInt64ThrowsForTryingToReadOutsideData()
        {
            byte[] randomData = new byte[1];
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanReader reader = new SpanReader(randomData);
                reader.ReadUInt64();
            });
        }

        [Fact]
        internal void AllReadersReadCorrectlyAndAdvanceIndex()
        {
            int size = 20; //Must be above 15 in order to test all methods (1 + 2 + 4 + 8 + >0)
            byte[] randomData = RandomNumberGenerator.GetBytes(size);
            SpanReader reader = new SpanReader(randomData);

            int expectedIndex = 0;
            byte expectedByte = randomData[expectedIndex++];
            byte actualByte = reader.ReadByte();

            ushort expectedUshort = BinaryPrimitives.ReadUInt16LittleEndian(randomData[expectedIndex..]);
            ushort actualUshort = reader.ReadUInt16();
            expectedIndex += 2;

            uint expectedUint = BinaryPrimitives.ReadUInt32LittleEndian(randomData[expectedIndex..]);
            uint actualUint = reader.ReadUInt32();
            expectedIndex += 4;

            ulong expectedUlong = BinaryPrimitives.ReadUInt64LittleEndian(randomData[expectedIndex..]);
            ulong actualUlong = reader.ReadUInt64();
            expectedIndex += 8;

            byte[] expectedBytes = randomData[expectedIndex..];
            using (ISecureBuffer actualBytes = reader.ReadBytes(size - expectedIndex))
            {
                Assert.True(actualBytes.AsSpan.SequenceEqual(expectedBytes));
            }
            Assert.Equal(expectedByte, actualByte);
            Assert.Equal(expectedUshort, actualUshort);
            Assert.Equal(expectedUint, actualUint);
            Assert.Equal(expectedUlong, actualUlong);
            
        }
        #endregion

        #region SpanWriter
        [Fact]
        internal void SpanWriterThrowsForEmptyData()
        {
            Assert.Throws<ArgumentException>(() => new SpanWriter(new byte[0]));
        }

        [Fact]
        internal void WriteByteWritesCorrectlyAndAdvancesIndex()
        {
            byte[] oldBytes = new byte[10];
            Random.Shared.NextBytes(oldBytes);
            byte[] newBytes = new byte[10];

            SpanWriter writer = new SpanWriter(oldBytes);
            for (int i = 0; i < newBytes.Length; i++)
            {
                writer.WriteByte(newBytes[i]);
            }

            Assert.True(oldBytes.SequenceEqual(newBytes));
        }

        [Fact]
        internal void WriteByteThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteByte(0);
                writer.WriteByte(0);
            });
        }

        [Fact]
        internal void WriteSpanWritesCorrectlyAndAdvancesIndex()
        {
            byte[] oldBytes = new byte[10];
            Random.Shared.NextBytes(oldBytes);
            byte[] newBytes = new byte[10];

            SpanWriter writer = new SpanWriter(oldBytes);
            writer.WriteSpan(newBytes);

            Assert.True(oldBytes.SequenceEqual(newBytes));
        }

        [Fact]
        internal void WriteSpanThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteSpan(new byte[2]);
            });
        }

        [Fact]
        internal void WriteUInt16WritesCorrectlyAndAdvancesIndex()
        {
            ushort expected = 10;
            byte[] expectedBytes = BitConverter.GetBytes(expected);
            byte[] actualBytes = new byte[sizeof(ushort)];
            SpanWriter writer = new SpanWriter(actualBytes);
            writer.WriteUInt16(expected);

            Assert.True(expectedBytes.SequenceEqual(actualBytes));
        }

        [Fact]
        internal void WriteUInt16ThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteUInt16(1000);
            });
        }

        [Fact]
        internal void WriteUInt32WritesCorrectlyAndAdvancesIndex()
        {
            uint expected = 100;
            byte[] expectedBytes = BitConverter.GetBytes(expected);
            byte[] actualBytes = new byte[sizeof(uint)];
            SpanWriter writer = new SpanWriter(actualBytes);
            writer.WriteUInt32(expected);

            Assert.True(expectedBytes.SequenceEqual(actualBytes));
        }

        [Fact]
        internal void WriteUInt32ThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteUInt32(1000);
            });
        }

        [Fact]
        internal void WriteUInt64WritesCorrectlyAndAdvancesIndex()
        {
            ulong expected = 1000;
            byte[] expectedBytes = BitConverter.GetBytes(expected);
            byte[] actualBytes = new byte[sizeof(ulong)];
            SpanWriter writer = new SpanWriter(actualBytes);
            writer.WriteUInt64(expected);

            Assert.True(expectedBytes.SequenceEqual(actualBytes));
        }

        [Fact]
        internal void WriteUInt64ThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteUInt64(1000);
            });
        }

        [Fact]
        internal void AllWritersWriteCorrectlyAndAdvanceIndex()
        {
            byte[] expectedSmallSpan = new byte[10] { 148, 2, 160, 228, 25, 108, 7, 15, 127, 6 };
            byte[] expectedSpan = new byte[25] { 1, 10, 0, 100, 0, 0, 0, 232, 3, 0, 0, 0, 0, 0, 0, 148, 2, 160, 228, 25, 108, 7, 15, 127, 6 };

            byte[] actualBytes = new byte[25];
            SpanWriter writer = new SpanWriter(actualBytes);
            writer.WriteByte(1);
            writer.WriteUInt16(10);
            writer.WriteUInt32(100);
            writer.WriteUInt64(1000);
            writer.WriteSpan(expectedSmallSpan);

            Assert.Equal(expectedSpan, actualBytes);
        }

        #endregion
    }
}
