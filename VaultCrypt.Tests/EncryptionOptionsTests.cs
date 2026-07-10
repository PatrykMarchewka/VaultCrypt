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
            _fileEncryptionOptions = new EncryptionOptions.FileEncryptionOptions(VaultCrypt.Services.EncryptionOptionsService.NewestFileEncryptionOptions, fileName, 1234, 1, false, null);
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
        internal void DifferentConstructorsReturnSameData()
        {
            string fileName = "string";
            using (ISecureBuffer fileNameBuffer = SecureBuffer.Create(Encoding.Unicode.GetByteCount(fileName)))
            {
                Encoding.Unicode.GetBytes(fileName).CopyTo(fileNameBuffer.AsSpan);

                using var encryptionOptions = new EncryptionOptions.FileEncryptionOptions(0, fileNameBuffer, 1, 2, false, null);
                using var encryptionOptions2 = new EncryptionOptions.FileEncryptionOptions(0, fileName, 1, 2, false, null);

                Assert.Equal(encryptionOptions, encryptionOptions2);
            }
        }

        [Fact]
        internal void GetFileNameReturnsCorrectString()
        {
            string expected = "EncryptionOptionsTestNoChunk";
            Assert.Equal(expected, _fileEncryptionOptions.GetFileName());
        }

        [Fact]
        internal void EncryptionOptionsThrowsForIncorrectChunkedFlag()
        {
            Assert.Throws<ArgumentException>(() => new EncryptionOptions.FileEncryptionOptions(0, "fileName", 11, 1, true, null));
        }

        [Fact]
        internal void EncryptionOptionsDeserializeThrowsForEmptyData()
        {
            Assert.Throws<ArgumentException>(() => EncryptionOptions.FileEncryptionOptionsReader.Deserialize(TestsHelper.EmptySecureBuffer));
        }

        [Fact]
        internal void EncryptionOptionsDeserializeThrowsForWrongVersion()
        {
            using (ISecureBuffer buffer = SecureBuffer.Create(1))
            {
                buffer.AsSpan[0] = byte.MaxValue;
                Assert.Throws<VaultCrypt.Exceptions.VaultEncryptionOptionsOperationException>(() => EncryptionOptions.FileEncryptionOptionsReader.Deserialize(buffer));
            }

        }

        [Fact]
        internal void EncryptionOptionsSerializeAndDeserializeCorrectlyNoChunk()
        {
            using (ISecureBuffer serialized = EncryptionOptions.FileEncryptionOptions.SerializeFileEncryptionOptions(_fileEncryptionOptions))
            {
                using var deserialized = EncryptionOptions.FileEncryptionOptionsReader.Deserialize(serialized);

                Assert.Equal(_fileEncryptionOptions, deserialized);
            }
        }

        [Fact]
        internal void EncryptionOptionsSerializeAndDeserializeCorrectlyWithChunk()
        {
            CreateEncryptionOptionsWithChunkInformation();

            using (ISecureBuffer serialized = EncryptionOptions.FileEncryptionOptions.SerializeFileEncryptionOptions(_fileEncryptionOptions))
            {
                using var deserialized = EncryptionOptions.FileEncryptionOptionsReader.Deserialize(serialized);

                Assert.Equal(_fileEncryptionOptions, deserialized);
            }
        }

        [Fact]
        internal void EncryptionOptionsDisposesProperlyNoChunk()
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
        internal void EncryptionOptionsDisposesProperlyWithChunk()
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
        internal void EncryptionOptionsThrowsForTooLongFileName()
        {
            using (ISecureBuffer buffer = SecureBuffer.Create(ushort.MaxValue + 1))
            {
                Assert.Throws<OverflowException>(() => new EncryptionOptions.FileEncryptionOptions(0, buffer, 0, 0, false, null));
            }
        }

        [Fact]
        internal void EncryptionOptionsThrowsForTooLongFileNameSecondConstructor()
        {
            string longName = new string('a', ushort.MaxValue + 1);
            Assert.Throws<OverflowException>(() => new EncryptionOptions.FileEncryptionOptions(0, longName, 0, 0, false, null));
        }

        [Fact]
        internal void EncryptionOptionsEqualsReturnsTrueForItself()
        {
            Assert.True(_fileEncryptionOptions.Equals(_fileEncryptionOptions));
        }

        [Fact]
        internal void EncryptionOptionsEqualsReturnsFalseForNull()
        {
            Assert.False(_fileEncryptionOptions.Equals(null));
        }

        [Fact]
        internal void EncryptionOptionsEqualsReturnsFalseForDifferentVersion()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "DifferentValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(1, "DifferentValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));

            Assert.False(first.Equals(second));
        }

        [Fact]
        internal void EncryptionOptionsEqualsReturnsFalseForDifferentName()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "Name", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "name", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));

            Assert.False(first.Equals(second));
        }

        [Fact]
        internal void EncryptionOptionsEqualsReturnsFalseForDifferentFileSize()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "DifferentValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "DifferentValue", 12, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));

            Assert.False(first.Equals(second));
        }

        [Fact]
        internal void EncryptionOptionsEqualsReturnsFalseForDifferentAlgorithm()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "DifferentValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "DifferentValue", 11, 2, true, new EncryptionOptions.ChunkInformation(1, 2, 3));

            Assert.False(first.Equals(second));
        }

        [Fact]
        internal void EncryptionOptionsEqualsReturnsFalseForDifferentChunkInformation()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "DifferentValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "DifferentValue", 11, 1, true, new EncryptionOptions.ChunkInformation(2, 2, 3));

            Assert.False(first.Equals(second));
        }

        [Fact]
        internal void EncryptionOptionsEqualsReturnsTrueForSameValuesDifferentReference()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));

            Assert.Equal(first, second);
            Assert.True(first.Equals(second));
        }

        [Fact]
        internal void EncryptionOptionsGetHashCodeReturnsSameHashForSameValuesDifferentReference()
        {
            using var first = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));
            using var second = new EncryptionOptions.FileEncryptionOptions(0, "SameValue", 11, 1, true, new EncryptionOptions.ChunkInformation(1, 2, 3));

            Assert.Equal(first.GetHashCode(), second.GetHashCode());
        }

        [Fact]
        internal void EncryptionOptionsReaderThrowsForEmptyData()
        {
            Assert.Throws<ArgumentException>(() => EncryptionOptions.FileEncryptionOptionsReader.Deserialize(TestsHelper.EmptySecureBuffer));
        }

        [Fact]
        internal void EncryptionOptionsReaderThrowsForWrongVersion()
        {
            using (ISecureBuffer buffer = SecureBuffer.Create(1))
            {
                buffer.AsSpan[0] = byte.MaxValue;
                Assert.Throws<VaultCrypt.Exceptions.VaultEncryptionOptionsOperationException>(() => EncryptionOptions.FileEncryptionOptionsReader.Deserialize(buffer));
            }
        }
    }
}
