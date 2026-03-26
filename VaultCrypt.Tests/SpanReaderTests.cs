using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class SpanReaderTests
    {
        [Fact]
        void SpanReaderThrowsForEmptyData()
        {
            Assert.Throws<ArgumentException>(() => new SpanReader(new byte[0]));
        }

        [Fact]
        void ReadByteReadsCorrectlyAndAdvancesIndex()
        {
            byte[] expected = RandomNumberGenerator.GetBytes(10);
            SpanReader reader = new SpanReader(expected);
            for (int i = 0; i < 10; i++)
            {
                Assert.Equal(expected[i], reader.ReadByte());
            }
        }

        [Fact]
        void ReadByteThrowsForTryingToReadOutsideData()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                SpanReader reader = new SpanReader(new byte[1]);
                reader.ReadByte();
                reader.ReadByte();
            });
        }

        [Fact]
        void ReadBytesReadsCorrectlyAndAdvancesIndex()
        {
            int size = RandomNumberGenerator.GetInt32(1, 100);
            byte[] randomData = RandomNumberGenerator.GetBytes(size);
            SpanReader reader = new SpanReader(randomData);

            for (int i = 0; i < size;)
            {
                //+1 because second parameter is exclusive
                int numberToRead = RandomNumberGenerator.GetInt32(1, (size - i) + 1);
                byte[] expected = randomData.AsSpan().Slice(i, numberToRead).ToArray();
                byte[] actual = reader.ReadBytes(numberToRead);
                Assert.True(expected.SequenceEqual(actual));
                i += numberToRead;
            }
        }

        [Fact]
        void ReadBytesThrowsForTryingToReadOutsideData()
        {
            int size = RandomNumberGenerator.GetInt32(1, 100);
            byte[] randomData = RandomNumberGenerator.GetBytes(size);
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                SpanReader reader = new SpanReader(randomData);
                reader.ReadBytes(size + 1);
            });
        }

        [Fact]
        void ReadUInt16ReadsCorrectlyAndAdvancesIndex()
        {
            int size = RandomNumberGenerator.GetInt32(2, 100);
            byte[] randomData = RandomNumberGenerator.GetBytes(size);
            SpanReader reader = new SpanReader(randomData);

            for (int i = 0; i < size - 2; i += 2)
            {
                ushort expected = BinaryPrimitives.ReadUInt16LittleEndian(randomData.AsSpan().Slice(i, 2));
                ushort actual = reader.ReadUInt16();
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        void ReadUInt16ThrowsForTryingToReadOutsideData()
        {
            int size = RandomNumberGenerator.GetInt32(1, 2);
            byte[] randomData = RandomNumberGenerator.GetBytes(size);
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                SpanReader reader = new SpanReader(randomData);
                reader.ReadUInt16();
            });
        }

        [Fact]
        void ReadUInt32ReadsCorrectlyAndAdvancesIndex()
        {
            int size = RandomNumberGenerator.GetInt32(4, 100);
            byte[] randomData = RandomNumberGenerator.GetBytes(size);
            SpanReader reader = new SpanReader(randomData);

            for (int i = 0; i < size - 4; i += 4)
            {
                uint expected = BinaryPrimitives.ReadUInt32LittleEndian(randomData.AsSpan().Slice(i, 4));
                uint actual = reader.ReadUInt32();
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        void ReadUInt32ThrowsForTryingToReadOutsideData()
        {
            int size = RandomNumberGenerator.GetInt32(1, 4);
            byte[] randomData = RandomNumberGenerator.GetBytes(size);
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                SpanReader reader = new SpanReader(randomData);
                reader.ReadUInt32();
            });
        }

        [Fact]
        void ReadUInt64ReadsCorrectlyAndAdvancesIndex()
        {
            int size = RandomNumberGenerator.GetInt32(8, 100);
            byte[] randomData = RandomNumberGenerator.GetBytes(size);
            SpanReader reader = new SpanReader(randomData);

            for (int i = 0; i < size - 8; i += 8)
            {
                ulong expected = BinaryPrimitives.ReadUInt64LittleEndian(randomData.AsSpan().Slice(i, 8));
                ulong actual = reader.ReadUInt64();
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        void ReadUInt64ThrowsForTryingToReadOutsideData()
        {
            int size = RandomNumberGenerator.GetInt32(1, 8);
            byte[] randomData = RandomNumberGenerator.GetBytes(size);
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                SpanReader reader = new SpanReader(randomData);
                reader.ReadUInt64();
            });
        }

        [Fact]
        void AllReadersReadCorrectlyAndAdvanceIndex()
        {
            int size = RandomNumberGenerator.GetInt32(20, 100);
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
            byte[] actualBytes = reader.ReadBytes(size - expectedIndex);

            Assert.Equal(expectedByte, actualByte);
            Assert.Equal(expectedUshort, actualUshort);
            Assert.Equal(expectedUint, actualUint);
            Assert.Equal(expectedUlong, actualUlong);
            Assert.True(expectedBytes.SequenceEqual(actualBytes));
        }

    }
}
