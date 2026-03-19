using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt.Tests.Services
{
    public class FileServiceTests
    {

        private readonly VaultCrypt.Services.FileService _service = new VaultCrypt.Services.FileService();

        [Fact]
        void WriteReadyChunkWritesToStream()
        {
            var bytes = new byte[] { 0, 1, 2 };
            var copy = (byte[])bytes.Clone();
            int nextToWrite = 0;
            var dictionary = new ConcurrentDictionary<int, byte[]>() { [0] = bytes };
            var stream = new MemoryStream();

            _service.WriteReadyChunk(dictionary, ref nextToWrite, 0, stream, new object());
            //Checking if the data got zeroed after writing
            Assert.True(bytes.SequenceEqual(new byte[bytes.Length]));

            var result = stream.ToArray();
            Assert.True(copy.SequenceEqual(result));
        }

        [Fact]
        void WriteReadyChunkThrowsForNullValues()
        {
            int nextToWrite = 0;
            Assert.Throws<ArgumentNullException>(() => _service.WriteReadyChunk(null!, ref nextToWrite, 0, new MemoryStream(), new object()));
            Assert.Throws<ArgumentNullException>(() => _service.WriteReadyChunk(new(), ref nextToWrite, 0, null!, new object()));
            Assert.Throws<ArgumentNullException>(() => _service.WriteReadyChunk(new(), ref nextToWrite, 0, new MemoryStream(), null!));
        }

        [Fact]
        void WriteReadyChunkThrowsForNegativeValues()
        {
            int nextToWrite = -1;
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.WriteReadyChunk(new ConcurrentDictionary<int, byte[]>(), ref nextToWrite, -1, new MemoryStream(), new object()));
        }

        [Fact]
        void WriteReadyChunkThrowsForMissingChunk()
        {
            int nextToWrite = 0;
            Assert.Throws<VaultException>(() => _service.WriteReadyChunk(new ConcurrentDictionary<int, byte[]>(), ref nextToWrite, 0, new MemoryStream(), new object()));
        }

        [Fact]
        void ZeroOutPartOfFileZeroesStream()
        {
            var stream = new MemoryStream();
            var empty = new byte[32];
            var bytes = RandomNumberGenerator.GetBytes(32);
            stream.Write(bytes);
            Assert.False(empty.SequenceEqual(stream.ToArray()));
            stream.Write(bytes);

            _service.ZeroOutPartOfFile(stream, 32, (ulong)bytes.Length);
            byte[] firstHalf = new byte[32];
            byte[] secondHalf = new byte[32];
            stream.Position = 0;
            stream.Read(firstHalf, 0, firstHalf.Length);
            stream.Read(secondHalf, 0, secondHalf.Length);

            Assert.True(bytes.SequenceEqual(firstHalf));
            Assert.True(empty.SequenceEqual(secondHalf));
        }

        [Fact]
        void ZeroOutPartOfFileThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.ZeroOutPartOfFile(null!, 1, 2));
        }

        [Fact]
        void ZeroOutPartOfFileThrowsForNegativeValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.ZeroOutPartOfFile(new MemoryStream(), -1, 2));
        }

        [Fact]
        void ZeroOutPartOfFileThrowsForZeroValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.ZeroOutPartOfFile(new MemoryStream(), 1, 0));
        }

        [Fact]
        void CopyPartOfFileCopiesStream()
        {
            var stream1 = new MemoryStream();
            var stream2 = new MemoryStream();
            byte[] stream1Bytes = RandomNumberGenerator.GetBytes(32);
            byte[] stream2Bytes = RandomNumberGenerator.GetBytes(32);
            stream1.Write(stream1Bytes);
            stream2.Write(stream2Bytes);
            Assert.False(stream1Bytes.SequenceEqual(stream2Bytes));
            byte[] expected = new byte[10];
            stream1.Position = 20; //Setting the position after .Write() modified it
            stream1.Read(expected, 0, expected.Length);

            _service.CopyPartOfFile(stream1, 20, (ulong)expected.Length, stream2, 10);
            byte[] actual = new byte[10];
            stream2.Position = 10; //Setting the position after .CopyPartOfFile() modified it
            stream2.Read(actual, 0, actual.Length);

            Assert.True(expected.SequenceEqual(actual));
            Assert.False(stream1.ToArray().SequenceEqual(stream2.ToArray()));
        }

        [Fact]
        void CopyPartOfFileThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.CopyPartOfFile(null!, 1, 2, new MemoryStream(), 3));
            Assert.Throws<ArgumentNullException>(() => _service.CopyPartOfFile(new MemoryStream(), 1, 2, null!, 3));
        }

        [Fact]
        void CopyPartOfFileThrowsForNegativeValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CopyPartOfFile(new MemoryStream(), -1, 2, new MemoryStream(), 3));
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CopyPartOfFile(new MemoryStream(), 1, 2, new MemoryStream(), -3));
        }

        [Fact]
        void CopyPartOfFileThrowsForZeroValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CopyPartOfFile(new MemoryStream(), 1, 0, new MemoryStream(), 3));
        }
    }
}
