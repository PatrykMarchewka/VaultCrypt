using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class EncryptionOptionsTests
    {
        private EncryptionOptions.FileEncryptionOptions _fileEncryptionOptions;

        public EncryptionOptionsTests()
        {
            _fileEncryptionOptions = new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("EncryptionOptionsTestNoChunk"), 1234, 1, false, null);
        }

        private void CreateEncryptionOptionsWithChunkInformation()
        {
            _fileEncryptionOptions = new EncryptionOptions.FileEncryptionOptions(1, Encoding.UTF8.GetBytes("EncryptionOptionsTestWithChunk"), 1234, 1, true, new EncryptionOptions.ChunkInformation(16, 24, 131));
        }

        [Fact]
        void EncryptionOptionsThrowForIncorrectChunkedFlag()
        {
            Assert.Throws<ArgumentException>(() => new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("DifferentValues"), 11, 1, true, null));
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
            var serialized = EncryptionOptions.FileEncryptionOptions.SerializeFileEncryptionOptions(_fileEncryptionOptions);
            var deserialized = EncryptionOptions.FileEncryptionOptionsReader.Deserialize(serialized);

            Assert.Equal(_fileEncryptionOptions, deserialized);
        }

        [Fact]
        void EncryptionOptionsSerializeAndDeserializeCorrectlyWithChunk()
        {
            CreateEncryptionOptionsWithChunkInformation();
            var serialized = EncryptionOptions.FileEncryptionOptions.SerializeFileEncryptionOptions(_fileEncryptionOptions);
            var deserialized = EncryptionOptions.FileEncryptionOptionsReader.Deserialize(serialized);

            Assert.Equal(_fileEncryptionOptions, deserialized);
        }

        [Fact]
        void EncryptionOptionsDisposesProperlyNoChunk()
        {
            _fileEncryptionOptions.Dispose();

            Assert.Equal(0, _fileEncryptionOptions.Version);
            Assert.Equal(Array.Empty<byte>(), _fileEncryptionOptions.FileName);
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
            Assert.Equal(Array.Empty<byte>(), _fileEncryptionOptions.FileName);
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
            Assert.Throws<OverflowException>(() => new EncryptionOptions.FileEncryptionOptions(0, new byte[ushort.MaxValue + 1], 0, 0, false, null));
        }

        [Fact]
        void EncryptionOptionsEqualsReturnsFalseForNull()
        {
            Assert.False(_fileEncryptionOptions.Equals(null));
        }

        [Fact]
        void EncryptionOptionsEqualsReturnsFalseForDifferentName()
        {
            var first = new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("DifferentValues"), 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            var second = new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("AifferentValues"), 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));

            Assert.False(first.Equals(second));
        }

        [Fact]
        void EncryptionOptionsEqualsReturnsFalseForDifferentChunkInformation()
        {
            var first = new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("DifferentValues"), 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            var second = new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("DifferentValues"), 11, 1, true, new EncryptionOptions.ChunkInformation(2, 2, 3));

            Assert.False(first.Equals(second));
        }

        [Fact]
        void EncryptionOptionsEqualsReturnsTrueForSameValuesDifferentReference()
        {
            var first = new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("SameValues"), 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            var second = new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("SameValues"), 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));

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
            var first = new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("DifferentValues"), 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            var second = new EncryptionOptions.FileEncryptionOptions(0, Encoding.UTF8.GetBytes("DifferentValues"), 11, 1, true, new EncryptionOptions.ChunkInformation(2, 2, 3));

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
