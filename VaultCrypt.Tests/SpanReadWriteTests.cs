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
            Assert.Throws<InvalidOperationException>(() =>
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
                ReadOnlySpan<byte> expected = randomData.AsSpan().Slice(i, numberToRead);
                using (SecureBuffer.SecureLargeBuffer actual = reader.ReadBytes(numberToRead))
                {
                    Assert.True(actual.AsSpan.SequenceEqual(expected));
                }
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
        void ReadBytesThrowForNegativeValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                SpanReader reader = new SpanReader(RandomNumberGenerator.GetBytes(10));
                reader.ReadBytes(-1);
            });
        }

        [Fact]
        void ReadBytesThrowsForZeroValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                SpanReader reader = new SpanReader(RandomNumberGenerator.GetBytes(10));
                reader.ReadBytes(0);
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
            Assert.Throws<InvalidOperationException>(() =>
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
            Assert.Throws<InvalidOperationException>(() =>
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
            Assert.Throws<InvalidOperationException>(() =>
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
            using (SecureBuffer.SecureLargeBuffer actualBytes = reader.ReadBytes(size - expectedIndex))
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
        void SpanWriterThrowsForEmptyData()
        {
            Assert.Throws<ArgumentException>(() => new SpanWriter(new byte[0]));
        }

        [Fact]
        void WriteByteWritesCorrectlyAndAdvancesIndex()
        {
            byte[] oldBytes = new byte[10];
            RandomNumberGenerator.Fill(oldBytes);
            byte[] newBytes = new byte[10];
            RandomNumberGenerator.Fill(newBytes);

            SpanWriter writer = new SpanWriter(oldBytes);
            for (int i = 0; i < newBytes.Length; i++)
            {
                writer.WriteByte(newBytes[i]);
            }

            Assert.True(oldBytes.SequenceEqual(newBytes));
        }

        [Fact]
        void WriteByteThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteByte(0);
                writer.WriteByte(0);
            });
        }

        [Fact]
        void WriteSpanWritesCorrectlyAndAdvancesIndex()
        {
            byte[] oldBytes = new byte[10];
            RandomNumberGenerator.Fill(oldBytes);
            byte[] newBytes = new byte[10];
            RandomNumberGenerator.Fill(newBytes);

            SpanWriter writer = new SpanWriter(oldBytes);
            writer.WriteSpan(newBytes);

            Assert.True(oldBytes.SequenceEqual(newBytes));
        }

        [Fact]
        void WriteSpanThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteSpan(new byte[2]);
            });
        }

        [Fact]
        void WriteUInt16WritesCorrectlyAndAdvancesIndex()
        {
            ushort expected = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue);
            byte[] expectedBytes = BitConverter.GetBytes(expected);
            byte[] actualBytes = new byte[sizeof(ushort)];
            SpanWriter writer = new SpanWriter(actualBytes);
            writer.WriteUInt16(expected);

            Assert.True(expectedBytes.SequenceEqual(actualBytes));
        }

        [Fact]
        void WriteUInt16ThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteUInt16(1000);
            });
        }

        [Fact]
        void WriteUInt32WritesCorrectlyAndAdvancesIndex()
        {
            uint expected = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
            byte[] expectedBytes = BitConverter.GetBytes(expected);
            byte[] actualBytes = new byte[sizeof(uint)];
            SpanWriter writer = new SpanWriter(actualBytes);
            writer.WriteUInt32(expected);

            Assert.True(expectedBytes.SequenceEqual(actualBytes));
        }

        [Fact]
        void WriteUInt32ThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteUInt32(1000);
            });
        }

        [Fact]
        void WriteUInt64WritesCorrectlyAndAdvancesIndex()
        {
            ulong expected = (ulong)RandomNumberGenerator.GetInt32(int.MaxValue);
            byte[] expectedBytes = BitConverter.GetBytes(expected);
            byte[] actualBytes = new byte[sizeof(ulong)];
            SpanWriter writer = new SpanWriter(actualBytes);
            writer.WriteUInt64(expected);

            Assert.True(expectedBytes.SequenceEqual(actualBytes));
        }

        [Fact]
        void WriteUInt64ThrowsForTryingToWriteOutsideData()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                SpanWriter writer = new SpanWriter(new byte[1]);
                writer.WriteUInt64(1000);
            });
        }

        #endregion
    }
}
