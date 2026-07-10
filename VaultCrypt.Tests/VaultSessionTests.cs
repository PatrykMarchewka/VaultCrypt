using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class VaultSessionTests
    {
        private readonly VaultSession _session = TestsHelper.EmptySession;

        [Fact]
        internal void CreateSessionSetsValuesCorrectly()
        {
            byte version = 10;
            NormalizedPath vaultPath = NormalizedPath.From("CreateSessionTest");
            ReadOnlySpan<byte> password = new byte[] { 1, 2, 3 };
            ReadOnlySpan<byte> salt = new byte[] { 4, 5, 6 };
            int iterations = 1;
            //Precomputed key value
            byte[] precomputedKey = new byte[128] { 242, 189, 23, 238, 9, 148, 95, 145, 100, 59, 125, 206, 125, 65, 65, 0, 156, 7, 34, 24, 21, 49, 137, 109, 160, 87, 70, 172, 10, 202, 219, 55, 178, 197, 107, 46, 239, 1, 106, 48, 117, 172, 239, 177, 123, 189, 31, 222, 223, 174, 20, 134, 122, 191, 3, 144, 70, 75, 175, 143, 201, 203, 61, 65, 239, 112, 7, 116, 8, 174, 83, 136, 218, 39, 119, 42, 166, 246, 94, 32, 193, 242, 30, 220, 162, 90, 53, 105, 94, 51, 88, 118, 219, 159, 96, 163, 93, 6, 231, 141, 136, 207, 253, 224, 56, 150, 12, 108, 10, 194, 143, 217, 113, 170, 61, 92, 56, 0, 5, 187, 205, 136, 50, 196, 171, 78, 20, 149 };

            _session.CreateSession(version, vaultPath, password, salt, iterations);

            Assert.Equal(version, _session.VERSION);
            Assert.Equal(vaultPath, _session.VAULTPATH);
            Assert.True(_session.KEY.AsSpan[..PasswordHelper.KeySize].SequenceEqual(precomputedKey));
            Assert.Empty(_session.ENCRYPTED_FILES);
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidPaths), MemberType = typeof(TestsHelper))]
        internal void CreateSessionThrowsForInvalidPath(NormalizedPath path, Type expectedException)
        {
            Assert.Throws(expectedException, () => _session.CreateSession(0, vaultPath: path, new byte[1], new byte[1], 1));
        }

        [Fact]
        internal void CreateSessionThrowsForInvalidPassword()
        {
            Assert.Throws<ArgumentException>(() => _session.CreateSession(0, NormalizedPath.From("Test"), password: new Span<byte>(), new byte[1], 1));
        }

        [Fact]
        internal void CreateSessionThrowsForInvalidSalt()
        {
            Assert.Throws<ArgumentException>(() => _session.CreateSession(0, NormalizedPath.From("Test"), new byte[1], salt: new Span<byte>(), 1));
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        internal void CreateSessionThrowsForInvalidIterations(int iterations)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _session.CreateSession(0, NormalizedPath.From("Test"), new byte[1], new byte[1], iterations: iterations));
        }

        [Fact]
        internal void DisposeClearsValues()
        {
            _session.Dispose();

            Assert.True(_session.KEY.AsSpan.IndexOfAnyExcept((byte)0) == -1);
            Assert.Empty(_session.ENCRYPTED_FILES);
            Assert.Empty(_session.VAULTPATH);
        }

        [Fact]
        internal void RaiseEncryptedFileListUpdatedRaisesEvent()
        {
            int eventRaisedCount = 0;
            _session.EncryptedFilesListUpdated += () => eventRaisedCount++;
            _session.RaiseEncryptedFileListUpdated();
            Assert.Equal(1, eventRaisedCount);
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(PasswordHelper.KeySize + 1)]
        internal void GetSlicedKeyThrowsForInvalidKeySize(int keySize)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _session.GetSlicedKey(keySize));
        }

        [Fact]
        internal void GetSlicedKeyReturnsCorrectlySlicedKey()
        {
            var sliced = _session.GetSlicedKey(PasswordHelper.KeySize);

            Assert.True(_session.KEY.AsSpan[..PasswordHelper.KeySize].SequenceEqual(sliced));
        }
    }

    public class VaultRegistryTests
    {

        public static TheoryData<byte, Type> VaultRegistryValues = new TheoryData<byte, Type> {
            { 0, typeof(VaultV0Reader) }
        };

        [Theory]
        [MemberData(nameof(VaultRegistryValues))]
        internal void GetVaultReaderReturnsCorrectValue(byte version, Type readerType)
        {
            var reader = VaultRegistry.GetVaultReader(version);
            Assert.Equal(version, reader.Version);
            Assert.Equal(readerType, reader.GetType());
        }

        [Fact]
        internal void GetVaultReaderThrowsForNonExistentReader()
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultOperationException>(() => VaultRegistry.GetVaultReader(byte.MaxValue));
        }
    }

    public class VaultV0ReaderTests : VaultReaderTests<VaultV0ReaderTests>
    {
        private readonly IVaultReader _reader;
        protected override IVaultReader Reader => _reader;

        public VaultV0ReaderTests()
        {
            VaultSession.CurrentSession = TestsHelper.EmptySession;
            _reader = new VaultV0Reader();
        }
    }

    public abstract class VaultReaderTests<TSelf> where TSelf : VaultReaderTests<TSelf>, new()
    {
        protected abstract IVaultReader Reader { get; }

        [Fact]
        internal void ReadSaltReturnsCorrectValues()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version
            byte[] expectedSalt = new byte[Reader.SaltSize];
            Random.Shared.NextBytes(expectedSalt);
            stream.Write(expectedSalt);

            using (ISecureBuffer actualSalt = Reader.ReadSalt(stream))
            {
                Assert.True(actualSalt.AsSpan.SequenceEqual(expectedSalt));
            }
        }

        [Fact]
        internal void ReadSaltThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.ReadSalt(null!));
        }

        [Fact]
        internal void ReadIterationsNumberReturnsCorrectNumber()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version;
            stream.Write(new byte[Reader.SaltSize]);
            int expectedIterations = 1000;
            byte[] iterationsBytes = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(iterationsBytes, expectedIterations);
            stream.Write(iterationsBytes);

            int actualIterations = Reader.ReadIterationsNumber(stream);

            Assert.Equal(expectedIterations, actualIterations);
        }

        [Fact]
        internal void ReadIterationsNumberThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.ReadIterationsNumber(null!));
        }

        [Fact]
        internal void PrepareVaultHeaderReturnsCorrectValues()
        {
            byte[] expectedSalt = new byte[Reader.SaltSize];
            Random.Shared.NextBytes(expectedSalt);
            int expectedIterations = 100;

            using (ISecureBuffer actualHeader = Reader.PrepareVaultHeader(expectedSalt, expectedIterations))
            {
                Assert.Equal(1 + Reader.SaltSize + sizeof(int), actualHeader.AsSpan.Length);
                Assert.Equal(Reader.Version, actualHeader.AsSpan[0]);
                Assert.True(actualHeader.AsSpan.Slice(1, Reader.SaltSize).SequenceEqual(expectedSalt));
                Assert.Equal(expectedIterations, BinaryPrimitives.ReadInt32LittleEndian(actualHeader.AsSpan[^4..]));
            }
        }

        [Fact]
        internal void PrepareVaultHeaderThrowsForInvalidSalt()
        {
            Assert.Throws<ArgumentException>(() => Reader.PrepareVaultHeader(new byte[0], 1));
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        internal void PrepareVaultHeaderThrowsForInvalidIterations(int iterations)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Reader.PrepareVaultHeader(new byte[1], iterations));
        }

        [Fact]
        internal void ReadMetadataOffsetsReturnsCorrectValues()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version;
            stream.Write(new byte[Reader.SaltSize]);
            stream.Write(new byte[sizeof(int)]); //Iterations number for password
            //Prepare offsets and save to stream
            long[] expectedOffsets = new long[20] { 1516993386, 1960667175, 795147798, 785437801, 1436527869, 1134603164, 483333288, 488327207, 25271567, 1379949306, 227359735, 1444890024, 1587194139, 766360720, 1979668108, 101542036, 465492720, 470198721, 2062934061, 1031763385 };
            using (ISecureBuffer expectedOffsetsBuffer = SecureBuffer.Create(expectedOffsets.Length * sizeof(long)))
            {
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(expectedOffsetsBuffer);
                foreach (long offset in expectedOffsets)
                {
                    writer.WriteInt64(offset);
                }
                Reader.SaveMetadataOffsets(stream, expectedOffsetsBuffer);

                using (ISecureBuffer actualOffsetsBuffer = Reader.ReadMetadataOffsets(stream))
                {
                    Assert.Equal(expectedOffsetsBuffer.AsSpan.Length, actualOffsetsBuffer.AsSpan.Length);
                    Assert.True(expectedOffsetsBuffer.AsSpan.SequenceEqual(actualOffsetsBuffer.AsSpan));
                }
            }
        }

        [Fact]
        internal void ReadMetadataOffsetsThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.ReadMetadataOffsets(null!));
        }

        [Fact]
        internal void AddAndSaveMetadataOffsetsAddsCorrectly()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version;
            stream.Write(new byte[Reader.SaltSize]);
            stream.Write(new byte[sizeof(int)]); //Iterations number for password
            Reader.SaveMetadataOffsets(stream, TestsHelper.EmptySecureBuffer); //Add empty offsets

            Reader.AddAndSaveMetadataOffsets(stream, long.MaxValue);

            using (ISecureBuffer actualOffsets = Reader.ReadMetadataOffsets(stream))
            {
                Assert.Equal(sizeof(long), actualOffsets.AsSpan.Length);

                SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(actualOffsets);
                long actualOffset = reader.ReadInt64();
                Assert.Equal(long.MaxValue, actualOffset);
            }
        }

        [Fact]
        internal void AddAndSaveMetadataOffsetsThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.AddAndSaveMetadataOffsets(null!, 1));
        }

        [Theory]
        [InlineData(long.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        internal void AddAndSaveMetadataOffsetsThrowsForInvalidNewOffset(long newOffset)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Reader.AddAndSaveMetadataOffsets(new MemoryStream(), newOffset));
        }

        [Fact]
        internal void RemoveAndSaveMetadataOffsetsRemovesCorrectly()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version;
            stream.Write(new byte[Reader.SaltSize]);
            stream.Write(new byte[sizeof(int)]); //Iterations number for password

            using (ISecureBuffer offsets = SecureBuffer.Create(sizeof(long)))
            {
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(offsets);
                writer.WriteInt64(long.MaxValue);

                Reader.SaveMetadataOffsets(stream, offsets);
            }

            Reader.RemoveAndSaveMetadataOffsets(stream, 0);

            using (ISecureBuffer actualOffsets = Reader.ReadMetadataOffsets(stream))
            {
                Assert.Equal(0, actualOffsets.AsSpan.Length);
            }
        }

        [Fact]
        internal void RemoveAndSaveMetadataOffsetsThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.RemoveAndSaveMetadataOffsets(null!, 0));
        }


        [Fact]
        internal void SaveMetadataOffsetsSavesCorrectly()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version;
            stream.Write(new byte[Reader.SaltSize]);
            stream.Write(new byte[sizeof(int)]); //Iterations number for password

            using (ISecureBuffer offsets = SecureBuffer.Create(sizeof(long)))
            {
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(offsets);
                writer.WriteInt64(long.MaxValue);

                Reader.SaveMetadataOffsets(stream, offsets);
            }

            using (ISecureBuffer actualOffsets = Reader.ReadMetadataOffsets(stream))
            {
                Assert.Equal(sizeof(long), actualOffsets.AsSpan.Length);

                SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(actualOffsets);
                long actualOffset = reader.ReadInt64();
                Assert.Equal(long.MaxValue, actualOffset);
            }
        }

        [Fact]
        internal void SaveMetadataOffsetsReplacesAlreadyExistingOffsets()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version;
            stream.Write(new byte[Reader.SaltSize]);
            stream.Write(new byte[sizeof(int)]); //Iterations number for password

            using (ISecureBuffer oldOffsets = SecureBuffer.Create(5 * sizeof(long)))
            {
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(oldOffsets);
                writer.WriteInt64(1);
                writer.WriteInt64(2);
                writer.WriteInt64(3);
                writer.WriteInt64(4);
                writer.WriteInt64(5);

                Reader.SaveMetadataOffsets(stream, oldOffsets);
            }

            using (ISecureBuffer newOffsets = SecureBuffer.Create(sizeof(long)))
            {
                SecureBufferReadWrite.SecureBufferWriter writer = new SecureBufferReadWrite.SecureBufferWriter(newOffsets);
                writer.WriteInt64(long.MaxValue);

                Reader.SaveMetadataOffsets(stream, newOffsets);
            }

            using (ISecureBuffer actualOffsets = Reader.ReadMetadataOffsets(stream))
            {
                Assert.Equal(sizeof(long), actualOffsets.AsSpan.Length);

                SecureBufferReadWrite.SecureBufferReader reader = new SecureBufferReadWrite.SecureBufferReader(actualOffsets);
                long actualOffset = reader.ReadInt64();
                Assert.Equal(long.MaxValue, actualOffset);
            }
        }

        [Fact]
        internal void SaveMetadataOffsetsThrowsOnInvalidStream()
        {
            using (ISecureBuffer buffer = SecureBuffer.Create(1))
            {
                Assert.Throws<ArgumentNullException>(() => Reader.SaveMetadataOffsets(null!, buffer));
            }
        }

        [Fact]
        internal void SaveMetadataOffsetsThrowsOnInvalidOffsets()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.SaveMetadataOffsets(new MemoryStream(), null!));
        }

        [Fact]
        internal void ReadAndDecryptDataReturnsCorrectValues()
        {
            VaultSession.CurrentSession = TestsHelper.EmptySession;
            var stream = new MemoryStream();
            //Precomputed values for Reader.VaultEncryptionAlgorithm set to AES256GCM

            var encrypted = new byte[1052] { 190, 214, 96, 221, 64, 124, 102, 94, 121, 160, 89, 63, 111, 175, 255, 75, 160, 100, 95, 25, 213, 183, 233, 7, 97, 226, 31, 8, 168, 184, 17, 63, 121, 89, 237, 113, 240, 9, 217, 254, 113, 96, 3, 214, 128, 193, 222, 101, 109, 83, 179, 134, 141, 21, 147, 160, 154, 214, 30, 50, 119, 89, 73, 101, 83, 68, 157, 86, 152, 215, 60, 75, 251, 51, 20, 112, 109, 74, 195, 159, 41, 83, 127, 214, 150, 102, 216, 198, 225, 166, 19, 94, 167, 151, 247, 30, 58, 211, 164, 207, 77, 13, 60, 15, 163, 136, 32, 194, 27, 213, 236, 53, 160, 179, 52, 25, 255, 228, 81, 174, 99, 64, 44, 178, 49, 229, 234, 199, 161, 167, 223, 3, 217, 205, 178, 233, 129, 155, 180, 145, 40, 107, 35, 64, 0, 106, 115, 201, 227, 86, 58, 30, 108, 207, 76, 43, 56, 23, 216, 211, 162, 30, 77, 137, 52, 49, 8, 205, 203, 49, 15, 132, 167, 37, 30, 230, 22, 152, 43, 175, 40, 123, 75, 170, 197, 8, 73, 203, 107, 102, 170, 56, 1, 116, 10, 177, 111, 48, 183, 10, 200, 93, 202, 235, 161, 158, 120, 243, 38, 64, 168, 177, 58, 54, 1, 17, 139, 221, 103, 209, 158, 255, 34, 144, 8, 188, 234, 160, 203, 240, 42, 37, 200, 240, 217, 28, 209, 32, 44, 69, 36, 208, 110, 34, 53, 70, 0, 36, 47, 197, 18, 110, 214, 157, 11, 204, 66, 249, 24, 213, 110, 137, 30, 252, 193, 221, 88, 220, 251, 184, 90, 189, 12, 61, 40, 7, 74, 236, 162, 224, 108, 61, 84, 25, 206, 100, 230, 91, 28, 92, 181, 11, 175, 164, 233, 166, 22, 193, 74, 15, 29, 118, 83, 130, 166, 248, 201, 94, 150, 153, 215, 97, 114, 39, 121, 232, 67, 98, 105, 49, 246, 195, 238, 49, 124, 185, 254, 74, 224, 50, 22, 206, 174, 38, 233, 159, 231, 96, 45, 12, 200, 10, 8, 93, 119, 182, 209, 1, 144, 241, 128, 6, 33, 47, 179, 155, 80, 121, 185, 57, 212, 241, 31, 135, 175, 192, 61, 22, 230, 2, 229, 241, 120, 128, 135, 196, 39, 233, 112, 216, 181, 66, 80, 165, 160, 75, 196, 184, 4, 236, 232, 236, 98, 90, 65, 22, 198, 0, 128, 90, 49, 109, 101, 198, 226, 147, 8, 209, 192, 88, 111, 39, 188, 176, 44, 160, 70, 183, 158, 47, 162, 35, 87, 74, 117, 28, 57, 39, 26, 49, 100, 96, 232, 175, 253, 246, 123, 40, 131, 110, 17, 232, 12, 231, 59, 190, 155, 126, 71, 138, 51, 131, 118, 47, 239, 95, 111, 130, 228, 223, 82, 160, 156, 46, 235, 78, 36, 210, 23, 184, 234, 148, 158, 182, 52, 145, 65, 145, 144, 106, 147, 79, 30, 144, 16, 29, 224, 214, 102, 213, 192, 193, 67, 131, 119, 220, 212, 226, 227, 176, 23, 169, 52, 179, 111, 198, 243, 66, 182, 173, 67, 236, 19, 122, 146, 133, 169, 77, 47, 6, 42, 87, 192, 115, 17, 128, 7, 224, 123, 253, 202, 170, 91, 150, 82, 172, 19, 226, 10, 200, 190, 102, 78, 147, 108, 218, 7, 70, 171, 124, 161, 239, 190, 43, 94, 86, 192, 187, 92, 76, 7, 201, 35, 20, 64, 16, 100, 205, 197, 21, 91, 168, 147, 100, 227, 57, 23, 238, 186, 159, 84, 192, 84, 117, 221, 5, 121, 155, 66, 231, 28, 123, 106, 91, 148, 84, 39, 20, 131, 32, 198, 73, 123, 202, 17, 205, 85, 205, 247, 56, 102, 239, 120, 171, 59, 190, 161, 105, 45, 117, 168, 198, 139, 149, 40, 1, 122, 60, 249, 191, 133, 255, 120, 64, 235, 207, 62, 38, 37, 78, 206, 68, 193, 135, 154, 52, 231, 18, 25, 109, 177, 70, 109, 142, 50, 85, 139, 204, 208, 232, 180, 131, 132, 114, 100, 103, 8, 61, 89, 197, 146, 239, 251, 37, 132, 99, 192, 147, 122, 141, 43, 82, 174, 144, 81, 50, 76, 11, 29, 153, 13, 113, 91, 35, 131, 42, 78, 100, 193, 26, 17, 210, 179, 29, 186, 9, 23, 75, 215, 224, 158, 112, 244, 221, 76, 246, 245, 38, 57, 253, 223, 221, 35, 196, 8, 101, 241, 233, 214, 227, 176, 147, 231, 132, 85, 230, 211, 179, 254, 68, 42, 164, 81, 114, 85, 214, 4, 70, 229, 184, 225, 80, 172, 174, 6, 242, 101, 8, 84, 2, 27, 21, 181, 246, 15, 215, 184, 209, 221, 85, 26, 151, 223, 67, 166, 72, 43, 74, 85, 94, 7, 253, 171, 98, 82, 140, 181, 91, 39, 132, 228, 82, 24, 74, 33, 249, 132, 238, 107, 31, 134, 187, 77, 36, 244, 40, 63, 138, 104, 152, 193, 150, 66, 72, 247, 255, 169, 122, 196, 45, 209, 136, 224, 186, 160, 54, 41, 153, 63, 37, 171, 166, 97, 157, 34, 96, 176, 8, 167, 105, 141, 217, 159, 133, 214, 240, 247, 182, 182, 87, 197, 59, 143, 240, 177, 216, 151, 67, 129, 15, 49, 199, 79, 30, 9, 166, 224, 95, 70, 51, 213, 161, 83, 0, 251, 150, 3, 103, 234, 205, 183, 159, 24, 7, 183, 87, 144, 228, 105, 173, 0, 186, 157, 154, 132, 123, 25, 40, 169, 9, 147, 201, 51, 55, 163, 158, 54, 188, 64, 177, 33, 63, 204, 58, 51, 78, 90, 32, 192, 62, 135, 176, 101, 0, 77, 231, 139, 213, 179, 213, 53, 143, 206, 210, 94, 19, 113, 253, 43, 226, 94, 220, 130, 168, 97, 250, 171, 21, 80, 69, 188, 165, 120, 74, 170, 8, 151, 203, 252, 134, 166, 148, 78, 198, 191, 80, 142, 41, 71, 231, 167, 113, 14, 200, 70, 48, 56, 42, 245, 158, 63, 161, 8, 180, 0, 165, 44, 230, 206, 98, 25, 194, 194, 104, 26, 51, 87, 228, 101, 167, 230, 24, 29, 103, 58, 43, 142, 246, 29, 29, 177, 31, 232, 8, 161, 90, 248, 42, 224, 106, 187, 199, 189, 217, 59, 189, 103, 156, 164, 167, 65, 59, 197, 23, 78, 60, 91, 224, 32, 137, 176, 192, 14, 46, 72, 77, 210, 70, 234, 74, 78, 197 };
            var expectedDecrypted = new byte[1024] { 188, 72, 236, 119, 104, 111, 12, 51, 110, 35, 30, 47, 31, 10, 196, 1, 32, 13, 117, 112, 11, 219, 198, 192, 250, 57, 4, 207, 141, 209, 122, 36, 34, 5, 8, 112, 18, 188, 112, 76, 126, 151, 49, 187, 40, 119, 232, 122, 34, 134, 199, 28, 56, 57, 175, 229, 151, 200, 181, 8, 208, 194, 7, 37, 11, 196, 223, 116, 81, 140, 15, 111, 99, 175, 75, 59, 140, 202, 97, 77, 38, 127, 253, 35, 14, 174, 194, 128, 93, 223, 74, 223, 134, 218, 28, 73, 231, 138, 219, 153, 59, 174, 49, 191, 162, 8, 87, 189, 83, 77, 55, 56, 170, 234, 58, 166, 151, 181, 26, 131, 84, 66, 235, 85, 37, 167, 41, 3, 104, 215, 203, 229, 190, 4, 195, 211, 254, 105, 16, 85, 66, 90, 68, 40, 150, 27, 189, 199, 42, 56, 155, 33, 19, 210, 110, 42, 21, 135, 33, 19, 147, 70, 77, 239, 228, 164, 6, 238, 158, 33, 31, 116, 150, 162, 177, 178, 141, 23, 31, 114, 39, 251, 20, 182, 180, 255, 232, 14, 127, 112, 222, 188, 188, 51, 155, 151, 252, 202, 86, 18, 174, 101, 202, 71, 255, 180, 159, 213, 119, 118, 34, 127, 13, 94, 27, 153, 111, 84, 145, 190, 177, 123, 194, 30, 69, 155, 0, 54, 228, 223, 152, 186, 109, 116, 92, 118, 199, 180, 216, 209, 177, 38, 161, 104, 12, 201, 82, 34, 172, 154, 4, 94, 182, 30, 193, 33, 46, 18, 135, 44, 1, 153, 186, 99, 168, 121, 4, 5, 139, 131, 4, 214, 254, 62, 178, 238, 190, 182, 59, 175, 48, 208, 112, 173, 102, 221, 179, 236, 136, 233, 47, 48, 235, 12, 36, 21, 171, 150, 90, 112, 202, 91, 37, 165, 121, 209, 78, 16, 162, 171, 223, 79, 144, 69, 48, 162, 48, 5, 33, 62, 82, 70, 230, 81, 15, 122, 119, 222, 134, 134, 229, 242, 199, 47, 212, 7, 0, 208, 201, 128, 56, 180, 243, 51, 89, 52, 134, 187, 59, 22, 35, 248, 187, 220, 183, 21, 137, 103, 173, 123, 134, 6, 11, 190, 202, 129, 165, 82, 52, 46, 185, 159, 180, 167, 111, 231, 65, 105, 255, 134, 7, 104, 101, 132, 15, 146, 250, 94, 148, 72, 43, 233, 4, 63, 133, 203, 231, 56, 197, 202, 150, 136, 172, 165, 125, 5, 5, 98, 222, 180, 57, 31, 81, 225, 61, 224, 178, 62, 140, 70, 109, 251, 52, 208, 186, 61, 67, 0, 178, 32, 78, 131, 217, 140, 107, 187, 107, 7, 209, 158, 59, 147, 17, 199, 33, 103, 97, 24, 1, 17, 6, 234, 50, 76, 249, 190, 17, 123, 28, 25, 90, 203, 189, 246, 156, 188, 217, 204, 24, 40, 226, 228, 233, 198, 103, 255, 179, 65, 22, 229, 178, 161, 38, 183, 171, 176, 163, 143, 99, 218, 13, 30, 44, 178, 195, 95, 240, 126, 168, 84, 197, 191, 104, 128, 245, 35, 213, 255, 144, 103, 114, 207, 113, 62, 155, 99, 63, 80, 120, 65, 184, 95, 79, 85, 203, 114, 190, 101, 207, 63, 157, 9, 116, 66, 148, 207, 2, 30, 89, 105, 192, 6, 24, 2, 45, 121, 34, 139, 255, 68, 19, 106, 234, 99, 200, 34, 108, 217, 54, 35, 56, 39, 69, 224, 226, 41, 24, 87, 208, 106, 41, 11, 40, 65, 215, 38, 213, 195, 170, 255, 191, 33, 125, 106, 35, 243, 235, 68, 5, 72, 154, 194, 247, 183, 76, 103, 70, 205, 178, 65, 215, 45, 170, 206, 98, 106, 39, 60, 16, 148, 147, 81, 143, 154, 118, 248, 164, 192, 224, 253, 193, 165, 184, 195, 131, 123, 185, 48, 50, 29, 189, 182, 100, 80, 169, 254, 149, 138, 43, 40, 22, 191, 111, 177, 137, 65, 175, 178, 181, 187, 27, 97, 47, 156, 165, 224, 11, 56, 10, 145, 19, 218, 141, 210, 30, 145, 63, 4, 150, 149, 178, 231, 169, 177, 15, 160, 177, 163, 33, 16, 132, 88, 170, 229, 126, 30, 70, 215, 173, 187, 245, 116, 151, 86, 228, 253, 87, 244, 182, 242, 14, 159, 179, 54, 102, 157, 32, 129, 148, 140, 207, 88, 26, 19, 146, 37, 210, 97, 24, 146, 81, 240, 34, 199, 134, 95, 2, 156, 69, 161, 8, 45, 7, 206, 181, 54, 168, 36, 8, 214, 195, 160, 120, 205, 245, 16, 76, 148, 158, 230, 28, 77, 50, 99, 14, 156, 235, 221, 52, 255, 165, 196, 206, 170, 65, 168, 57, 14, 104, 204, 125, 43, 200, 197, 65, 102, 127, 122, 125, 215, 18, 231, 35, 130, 22, 234, 182, 238, 16, 210, 182, 25, 187, 96, 72, 16, 232, 86, 106, 91, 190, 125, 236, 79, 149, 164, 29, 177, 166, 200, 230, 6, 227, 59, 18, 208, 106, 114, 0, 169, 31, 173, 188, 86, 232, 93, 85, 47, 164, 212, 214, 85, 143, 79, 248, 18, 129, 105, 254, 150, 133, 12, 121, 48, 198, 14, 215, 70, 104, 255, 176, 30, 165, 56, 199, 154, 154, 90, 198, 99, 21, 39, 149, 32, 232, 213, 53, 127, 195, 123, 144, 101, 123, 193, 228, 163, 156, 91, 230, 89, 216, 173, 148, 69, 185, 51, 250, 219, 255, 198, 22, 72, 37, 173, 85, 16, 198, 167, 210, 121, 173, 53, 186, 43, 241, 245, 12, 128, 67, 52, 221, 200, 106, 162, 69, 132, 119, 194, 43, 125, 118, 152, 152, 73, 132, 19, 118, 74, 128, 180, 52, 46, 12, 104, 69, 140, 227, 229, 104, 183, 11, 73, 124, 31, 151, 162, 44, 231, 202, 7, 6, 99, 242, 183, 216, 244, 43, 175, 163, 141, 112, 202, 158, 42, 16, 54, 76, 187, 131, 90, 76, 29, 6, 83, 179, 127, 21, 209, 149, 222, 35, 51, 115, 196, 17, 167, 31, 62, 209, 218, 161, 81, 86, 163, 137, 14, 170, 175, 99, 47, 144, 224, 142, 238, 97, 221, 77, 57, 20, 14, 44, 121, 40, 59, 180, 88, 49, 74, 185, 106, 145, 128, 190, 221 };

            stream.Write(encrypted);
            var actualDecrypted = Reader.ReadAndDecryptData(stream, 0, 1052);

            Assert.True(actualDecrypted.AsSpan.SequenceEqual(expectedDecrypted));
        }

        [Fact]
        internal void ReadAndDecryptDataThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.ReadAndDecryptData(null!, 1, 1));
        }

        [Theory]
        [InlineData(long.MinValue)]
        [InlineData(-1)]
        internal void ReadAndDecryptDataThrowsForInvalidOffset(long offset)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Reader.ReadAndDecryptData(new MemoryStream(), offset, 1));
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        internal void ReadAndDecryptDataThrowsForInvalidLength(int length)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Reader.ReadAndDecryptData(new MemoryStream(), 1, length));
        }

        [Fact]
        internal void ReadAndDecryptDataThrowsForTooShortLength()
        {
            //Setup to prevent EndOfStreamException
            var stream = new MemoryStream();
            stream.Write(new byte[5] { 1, 2, 3, 4, 5 });
            //Thrown from VaultDecryption by passing data that has lower length than ExtraEncryptionDataSize of default vault encryption algorithm
            Assert.Throws<ArgumentException>(() => Reader.ReadAndDecryptData(stream, 1, 1));
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        internal void VaultEncryptionThrowsForInvalidData(byte[] data)
        {
            Assert.Throws<ArgumentException>(() => Reader.VaultEncryption(data));
        }

        [Fact]
        internal void ReaderWritesAndReadsHeaderCorrectly()
        {
            var stream = new MemoryStream();
            byte[] expectedSalt = new byte[Reader.SaltSize];
            Random.Shared.NextBytes(expectedSalt);
            int expectedIterations = 100;

            using (ISecureBuffer header = Reader.PrepareVaultHeader(expectedSalt, expectedIterations))
            {
                stream.Write(header.AsSpan);
            }

            using (ISecureBuffer actualSalt = Reader.ReadSalt(stream))
            {
                Assert.True(actualSalt.AsSpan.SequenceEqual(expectedSalt));
            }

            int actualIterations = Reader.ReadIterationsNumber(stream);
            Assert.Equal(expectedIterations, actualIterations);
        }

        [Fact]
        internal void VaultEncryptionAndVaultDecryptionWorkCorrectly()
        {
            var stream = new MemoryStream();
            //Random values to fill the beginning of stream in order to simulate actual vault
            byte[] streamPrefix = new byte[100] { 49, 216, 63, 76, 229, 168, 178, 21, 20, 130, 8, 212, 112, 92, 103, 71, 35, 83, 105, 78, 215, 10, 21, 68, 137, 203, 25, 30, 227, 212, 197, 33, 161, 17, 213, 216, 167, 41, 11, 59, 170, 103, 43, 242, 73, 174, 98, 219, 51, 44, 218, 218, 164, 45, 54, 214, 205, 215, 84, 108, 182, 80, 27, 102, 65, 165, 199, 92, 25, 171, 150, 68, 150, 94, 162, 74, 223, 165, 35, 109, 142, 79, 145, 48, 243, 32, 232, 230, 14, 141, 213, 151, 148, 128, 124, 24, 50, 40, 5, 191 };
            stream.Write(streamPrefix);

            byte[] expectedDecrypted = new byte[150] { 211, 191, 37, 169, 152, 160, 206, 194, 25, 54, 2, 52, 222, 92, 111, 14, 210, 235, 167, 62, 87, 134, 57, 24, 244, 82, 187, 58, 62, 148, 128, 64, 58, 9, 145, 113, 214, 32, 109, 164, 73, 69, 169, 151, 220, 98, 194, 113, 26, 18, 49, 44, 224, 147, 225, 129, 246, 214, 21, 235, 160, 9, 68, 233, 51, 142, 162, 145, 227, 221, 126, 181, 122, 112, 121, 173, 54, 185, 251, 144, 31, 4, 196, 221, 175, 84, 202, 177, 95, 82, 122, 26, 173, 117, 47, 1, 91, 166, 177, 48, 229, 141, 207, 25, 125, 47, 58, 161, 101, 255, 128, 17, 70, 158, 41, 101, 0, 0, 89, 164, 222, 147, 253, 127, 70, 131, 228, 183, 235, 151, 10, 80, 54, 112, 131, 77, 247, 74, 135, 198, 158, 201, 178, 87, 227, 220, 196, 164, 156, 11 };
            ISecureBuffer actualEncrypted = null!;
            ISecureBuffer actualDecrypted = null!;
            try
            {
                actualEncrypted = Reader.VaultEncryption(expectedDecrypted);
                stream.Write(actualEncrypted.AsSpan);

                //Random values to fill the end of stream in order to simulate actual vault
                byte[] streamSuffix = new byte[50] { 191, 46, 28, 27, 17, 194, 77, 222, 167, 159, 70, 200, 231, 102, 161, 146, 167, 122, 112, 57, 30, 92, 6, 238, 208, 245, 68, 53, 148, 60, 196, 6, 204, 167, 171, 77, 229, 204, 161, 16, 149, 91, 141, 35, 136, 90, 43, 221, 168, 127 };
                stream.Write(streamSuffix);

                actualDecrypted = Reader.ReadAndDecryptData(stream, streamPrefix.Length, actualEncrypted.AsSpan.Length);

                Assert.True(actualDecrypted.AsSpan.SequenceEqual(expectedDecrypted));
            }
            finally
            {
                actualEncrypted?.Dispose();
                actualDecrypted?.Dispose();
            }
        }
    }
}
