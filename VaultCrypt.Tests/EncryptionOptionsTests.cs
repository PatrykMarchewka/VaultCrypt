using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class EncryptionOptionsTests : IDisposable
    {
        private EncryptionOptions.FileEncryptionOptions _fileEncryptionOptions;

        public EncryptionOptionsTests()
        {
            string fileName = "EncryptionOptionsTestNoChunk";
            _fileEncryptionOptions = new EncryptionOptions.FileEncryptionOptions(0, fileName, 1234, 1, false, null);
        }

        public void Dispose()
        {
            _fileEncryptionOptions.Dispose();
        }

        private void CreateEncryptionOptionsWithChunkInformation()
        {
            string fileName = "EncryptionOptionsTestWithChunk";
            _fileEncryptionOptions = new EncryptionOptions.FileEncryptionOptions(1, fileName, 1234, 1, true, new EncryptionOptions.ChunkInformation(16, 24, 131));
        }

        [Fact]
        void DifferentConstructorsReturnSameData()
        {
            string fileName = "string";
            SecureBuffer.SecureLargeBuffer fileNameBuffer = new SecureBuffer.SecureLargeBuffer(Encoding.UTF8.GetByteCount(fileName));
            Encoding.UTF8.GetBytes(fileName).CopyTo(fileNameBuffer.AsSpan);

            using var encryptionOptions = new EncryptionOptions.FileEncryptionOptions(0, fileNameBuffer, 1, 2, false, null);
            using var encryptionOptions2 = new EncryptionOptions.FileEncryptionOptions(0, fileName, 1, 2, false, null);

            Assert.Equal(encryptionOptions, encryptionOptions2);
        }

        [Fact]
        void GetFileNameReturnsCorrectString()
        {
            string expected = "EncryptionOptionsTestNoChunk";
            Assert.Equal(expected, _fileEncryptionOptions.GetFileName());
        }

        [Fact]
        void EncryptionOptionsThrowForIncorrectChunkedFlag()
        {
            Assert.Throws<ArgumentException>(() => new EncryptionOptions.FileEncryptionOptions(0, "fileName", 11, 1, true, null));
        }

        [Fact]
        void EncryptionOptionsDeserializeThrowsForEmptyData()
        {
            Assert.Throws<ArgumentException>(() => EncryptionOptions.FileEncryptionOptionsReader.Deserialize(new ReadOnlySpan<byte>()));
        }

        [Fact]
        void EncryptionOptionsDeserializeThrowsForWrongVersion()
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultException>(() => EncryptionOptions.FileEncryptionOptionsReader.Deserialize(new byte[1] { byte.MaxValue }));

        }

        [Fact]
        void EncryptionOptionsSerializeAndDeserializeCorrectlyNoChunk()
        {
            using (SecureBuffer.SecureLargeBuffer serialized = EncryptionOptions.FileEncryptionOptions.SerializeFileEncryptionOptions(_fileEncryptionOptions))
            {
                using var deserialized = EncryptionOptions.FileEncryptionOptionsReader.Deserialize(serialized.AsSpan);

                Assert.Equal(_fileEncryptionOptions, deserialized);
            }
        }

        [Fact]
        void EncryptionOptionsSerializeAndDeserializeCorrectlyWithChunk()
        {
            CreateEncryptionOptionsWithChunkInformation();

            using (SecureBuffer.SecureLargeBuffer serialized = EncryptionOptions.FileEncryptionOptions.SerializeFileEncryptionOptions(_fileEncryptionOptions))
            {
                using var deserialized = EncryptionOptions.FileEncryptionOptionsReader.Deserialize(serialized.AsSpan);

                Assert.Equal(_fileEncryptionOptions, deserialized);
            }
        }

        [Fact]
        void EncryptionOptionsDisposesProperlyNoChunk()
        {
            _fileEncryptionOptions.Dispose();

            Assert.Equal(0, _fileEncryptionOptions.Version);
            Assert.Throws<ObjectDisposedException>(() => { var throws = _fileEncryptionOptions.FileName.AsSpan; });
            Assert.Equal<ulong>(0, _fileEncryptionOptions.FileSize);
            Assert.Equal(0, _fileEncryptionOptions.EncryptionAlgorithm);
            Assert.False(_fileEncryptionOptions.IsChunked);
            Assert.Null(_fileEncryptionOptions.ChunkInformation);

        }
        [Fact]
        void EncryptionOptionsDisposesProperlyWithChunk()
        {
            CreateEncryptionOptionsWithChunkInformation();
            EncryptionOptions.ChunkInformation copy = _fileEncryptionOptions.ChunkInformation!;

            _fileEncryptionOptions.Dispose();

            Assert.Equal(0, _fileEncryptionOptions.Version);
            Assert.Throws<ObjectDisposedException>(() => { var throws = _fileEncryptionOptions.FileName.AsSpan; });
            Assert.Equal<ulong>(0, _fileEncryptionOptions.FileSize);
            Assert.Equal(0, _fileEncryptionOptions.EncryptionAlgorithm);
            Assert.False(_fileEncryptionOptions.IsChunked);
            Assert.Null(_fileEncryptionOptions.ChunkInformation);

            Assert.Equal(0, copy.ChunkSize);
            Assert.Equal(0UL, copy.TotalChunks);
            Assert.Equal<uint>(0, copy.FinalChunkSize);

        }

        [Fact]
        void EncryptionOptionsThrowsForTooLongFileName()
        {
            using (SecureBuffer.SecureLargeBuffer buffer = new SecureBuffer.SecureLargeBuffer(ushort.MaxValue + 1))
            {
                Assert.Throws<OverflowException>(() => new EncryptionOptions.FileEncryptionOptions(0, buffer, 0, 0, false, null));
            }
        }

        [Fact]
        void EncryptionOptionsEqualsReturnsFalseForNull()
        {
            Assert.False(_fileEncryptionOptions.Equals(null));
        }

        [Fact]
        void EncryptionOptionsEqualsReturnsFalseForDifferentName()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "Name", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "name", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));

            Assert.False(first.Equals(second));
        }

        [Fact]
        void EncryptionOptionsEqualsReturnsFalseForDifferentChunkInformation()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(2, 2, 3));

            Assert.False(first.Equals(second));
        }

        [Fact]
        void EncryptionOptionsEqualsReturnsTrueForSameValuesDifferentReference()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(2, 2, 3));

            Assert.Equal(first, second);
            Assert.True(first.Equals(second));
        }

        [Fact]
        void EncryptionOptionsGetHashCodeReturnsSameHashForSameValues()
        {
            var copy = _fileEncryptionOptions;

            Assert.Equal(_fileEncryptionOptions.GetHashCode(), copy.GetHashCode());
        }

        [Fact]
        void EncryptionOptionsGetHashCodeReturnsDifferentHashForDifferentValues()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(2, 2, 3));

            Assert.NotEqual(first.GetHashCode(), second.GetHashCode());
        }


        [Fact]
        void EncryptionOptionsReaderThrowsForEmptyData()
        {
            Assert.Throws<ArgumentException>(() => EncryptionOptions.FileEncryptionOptionsReader.Deserialize(new ReadOnlySpan<byte>()));
        }

        [Fact]
        void EncryptionOptionsReaderThrowsForWrongVersion()
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultException>(() => EncryptionOptions.FileEncryptionOptionsReader.Deserialize(new byte[1] { byte.MaxValue }));
        }
    }
}
