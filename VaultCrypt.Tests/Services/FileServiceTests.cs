using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests.Services
{
    public class FileServiceTests
    {

        private readonly VaultCrypt.Services.FileService _service = new VaultCrypt.Services.FileService();

        [Fact]
        internal void WriteReadyChunkWritesToStream()
        {
            SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(100);
            SecureBuffer.SecureLargeBuffer copy = new SecureBuffer.SecureLargeBuffer(100);
            try
            {
                RandomNumberGenerator.Fill(buffer.AsSpan);
                buffer.AsSpan.CopyTo(copy.AsSpan);
                ulong nextToWrite = 0;
                var dictionary = new ConcurrentDictionary<ulong, SecureBuffer.SecureLargeBuffer>() { [0] = buffer };
                var stream = new MemoryStream();

                _service.WriteReadyChunk(dictionary, ref nextToWrite, 0, stream, new object());
                //Checking if the data got disposed after writing
                Assert.Throws<ObjectDisposedException>(() => buffer.AsMemory);

                var result = stream.ToArray();
                Assert.True(copy.AsSpan.SequenceEqual(result));
            }
            finally
            {
                buffer.Dispose();
                copy.Dispose();
            }
            
        }

        ulong nextToWrite = 0; //Passed to tests as ref value

        [Fact]
        internal void WriteReadyChunkThrowsForInvalidResults()
        {
            Assert.Throws<ArgumentNullException>(() => _service.WriteReadyChunk(null!, ref nextToWrite, 0, new MemoryStream(), new object()));
        }

        [Fact]
        internal void WriteReadyChunkThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => _service.WriteReadyChunk(new(), ref nextToWrite, 0, null!, new object()));
        }

        [Fact]
        internal void WriteReadyChunkThrowsForInvalidLock()
        {
            Assert.Throws<ArgumentNullException>(() => _service.WriteReadyChunk(new(), ref nextToWrite, 0, new MemoryStream(), null!));
        }

        [Fact]
        internal void WriteReadyChunkThrowsForMissingChunk()
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultIOOperationException>(() => _service.WriteReadyChunk(new(), ref nextToWrite, 0, new MemoryStream(), new object()));
        }

        [Fact]
        internal void ZeroOutPartOfFileZeroesStream()
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
        internal void ZeroOutPartOfFileThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => _service.ZeroOutPartOfFile(null!, 1, 2));
        }

        [Theory]
        [InlineData(long.MinValue)]
        [InlineData(-1)]
        internal void ZeroOutPartOfFileThrowsForInvalidOffset(long offset)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.ZeroOutPartOfFile(new MemoryStream(), offset, 2));
        }

        [Theory]
        [InlineData(0)]
        internal void ZeroOutPartOfFileThrowsForInvalidLength(ulong length)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.ZeroOutPartOfFile(new MemoryStream(), 1, length));
        }

        [Fact]
        internal void CopyPartOfFileCopiesStream()
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
        internal void CopyPartOfFileThrowsForInvalidSourceStream()
        {
            Assert.Throws<ArgumentNullException>(() => _service.CopyPartOfFile(null!, 1, 2, new MemoryStream(), 3));
        }

        [Theory]
        [InlineData(long.MinValue)]
        [InlineData(-1)]
        internal void CopyPartOfFileThrowsForInvalidOffset(long offset)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CopyPartOfFile(new MemoryStream(), offset, 2, new MemoryStream(), 3));
        }

        [Theory]
        [InlineData(0)]
        internal void CopyPartOfFileThrowsForInvalidLength(ulong length)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CopyPartOfFile(new MemoryStream(), 1, 0, new MemoryStream(), 3));
        }

        [Fact]
        internal void CopyPartOfFileThrowsForInvalidDestinationStream()
        {
            Assert.Throws<ArgumentNullException>(() => _service.CopyPartOfFile(new MemoryStream(), 1, 2, null!, 3));
        }

        [Theory]
        [InlineData(long.MinValue)]
        [InlineData(-1)]
        internal void CopyPartOfFileThrowsForInvalidDestinationOffset(long destinationOffset)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CopyPartOfFile(new MemoryStream(), 1, 2, new MemoryStream(), destinationOffset));
        }
    }
}
