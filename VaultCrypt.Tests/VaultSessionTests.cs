using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;
using VaultCrypt.Services;

namespace VaultCrypt.Tests
{
    public class VaultSessionTests
    {
        private readonly VaultSession _session;

        public VaultSessionTests()
        {
            _session = TestsHelper.CreateEmptySessionInstance();
        }

        private void SetKey(byte[] key)
        {
            _session.KEY.Dispose();
            SecureBuffer.SecureKeyBuffer keyBuffer = new SecureBuffer.SecureKeyBuffer(PasswordHelper.KeySize);
            key.CopyTo(keyBuffer.AsSpan);
            //Reflection to set the key value despite being private
            typeof(VaultSession).GetProperty(nameof(VaultSession.KEY))!.SetValue(_session, keyBuffer);
        }

        [Fact]
        void CreateSessionSetsValuesCorrectly()
        {
            NormalizedPath vaultPath = NormalizedPath.From("CreateSessionTest");
            IVaultReader reader = new FakeVaultReader();
            ReadOnlySpan<byte> password = new byte[] { 1, 2, 3 };
            ReadOnlySpan<byte> salt = new byte[] { 4, 5, 6 };
            int iterations = 1;
            //Precomputed key value
            byte[] precomputedKey = new byte[128] { 242, 189, 23, 238, 9, 148, 95, 145, 100, 59, 125, 206, 125, 65, 65, 0, 156, 7, 34, 24, 21, 49, 137, 109, 160, 87, 70, 172, 10, 202, 219, 55, 178, 197, 107, 46, 239, 1, 106, 48, 117, 172, 239, 177, 123, 189, 31, 222, 223, 174, 20, 134, 122, 191, 3, 144, 70, 75, 175, 143, 201, 203, 61, 65, 239, 112, 7, 116, 8, 174, 83, 136, 218, 39, 119, 42, 166, 246, 94, 32, 193, 242, 30, 220, 162, 90, 53, 105, 94, 51, 88, 118, 219, 159, 96, 163, 93, 6, 231, 141, 136, 207, 253, 224, 56, 150, 12, 108, 10, 194, 143, 217, 113, 170, 61, 92, 56, 0, 5, 187, 205, 136, 50, 196, 171, 78, 20, 149 };

            _session.CreateSession(vaultPath, reader, password, salt, iterations);

            Assert.Equal(vaultPath, _session.VAULTPATH);
            Assert.Equal(reader, _session.VAULT_READER);
            Assert.True(_session.KEY.AsSpan[..PasswordHelper.KeySize].SequenceEqual(precomputedKey));
            Assert.Empty(_session.ENCRYPTED_FILES);
        }

        [Fact]
        void DisposeClearsValues()
        {
            _session.Dispose();

            Assert.True(_session.KEY.AsSpan.SequenceEqual(new byte[_session.KEY.Length]));
            Assert.Empty(_session.ENCRYPTED_FILES);
            Assert.True(string.IsNullOrEmpty(_session.VAULTPATH) && _session.VAULTPATH is not null);
            Assert.Null(_session.VAULT_READER);
        }

        [Fact]
        void RaiseEncryptedFileListUpdatedRaisesEvent()
        {
            int eventRaisedCount = 0;
            _session.EncryptedFilesListUpdated += () => eventRaisedCount++;
            _session.RasiseEncryptedFileListUpdated();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        void GetSlicedKeyThrowsForTooBigSlice()
        {
            SetKey(new byte[] { 0, 1, 2 });
            Assert.Throws<ArgumentOutOfRangeException>(() => _session.GetSlicedKey(byte.MaxValue));
        }

        [Fact]
        void GetSlicedKeyReturnsCorrectlySlicedKey()
        {
            SetKey(new byte[] { 0, 1, 2 });
            var sliced = _session.GetSlicedKey(3);

            for (int i = 0; i < 3; i++)
            {
                Assert.Equal(_session.KEY.AsSpan[i], sliced[i]);
            }
        }
    }

    public class VaultRegistryTests
    {
        private readonly VaultRegistry _registry;
        public VaultRegistryTests()
        {
            _registry = TestsHelper.CreateVaultRegistry(null!);
        }

        [Fact]
        void GetVaultReaderReturnsCorrectValue()
        {
            var reader = _registry.GetVaultReader(0);
            Assert.Equal(0, reader.Version);
            Assert.True(reader is VaultV0Reader);
        }

        [Fact]
        void GetVaultReaderThrowsForNonExistentReader()
        {
            Assert.Throws<VaultException>(() => _registry.GetVaultReader(byte.MaxValue));
        }
    }

    public class VaultV0ReaderTests : VaultReaderTests<VaultV0ReaderTests>
    {
        private readonly IVaultReader _reader;
        private readonly IVaultSession _session;
        protected override IVaultReader Reader => _reader;
        protected override IVaultSession Session => _session;

        public VaultV0ReaderTests()
        {
            _session = TestsHelper.CreateFilledSessionInstanceWithReader();
            _reader = new VaultV0Reader(Session);
        }


        [Fact]
        void ReadAndDecryptDataReturnsCorrectValues()
        {
            var stream = new MemoryStream();
            //Precomputed values
            var encrypted = new byte[1052] { 62, 94, 212, 77, 139, 226, 57, 93, 192, 21, 18, 234, 49, 114, 31, 185, 123, 117, 209, 143, 43, 211, 253, 138, 213, 197, 153, 107, 101, 98, 183, 223, 210, 223, 147, 113, 212, 32, 91, 10, 92, 141, 14, 235, 206, 76, 252, 227, 20, 135, 245, 65, 15, 208, 112, 168, 130, 111, 4, 188, 76, 253, 125, 180, 38, 170, 246, 42, 61, 54, 253, 55, 225, 53, 177, 4, 109, 27, 210, 216, 250, 158, 213, 139, 109, 165, 72, 137, 57, 217, 249, 174, 245, 64, 16, 211, 33, 28, 194, 115, 211, 72, 20, 155, 164, 235, 248, 199, 188, 255, 231, 134, 105, 176, 175, 72, 243, 33, 75, 221, 110, 56, 197, 101, 39, 108, 147, 187, 115, 1, 232, 123, 99, 102, 238, 102, 226, 142, 170, 129, 26, 205, 175, 74, 135, 111, 243, 3, 231, 152, 70, 16, 198, 117, 85, 2, 184, 14, 214, 118, 95, 36, 197, 46, 187, 141, 212, 22, 233, 68, 210, 247, 188, 127, 160, 145, 96, 110, 225, 114, 229, 253, 41, 138, 241, 117, 103, 165, 65, 118, 141, 184, 26, 79, 134, 204, 131, 167, 206, 95, 159, 120, 115, 123, 206, 54, 233, 71, 75, 118, 179, 34, 159, 162, 88, 189, 34, 88, 168, 19, 5, 181, 168, 161, 103, 110, 123, 21, 161, 101, 54, 43, 197, 136, 222, 84, 59, 66, 98, 191, 234, 61, 4, 90, 32, 206, 11, 155, 1, 45, 161, 231, 71, 124, 69, 242, 237, 44, 127, 233, 28, 31, 69, 169, 251, 215, 140, 239, 140, 82, 188, 251, 213, 192, 243, 15, 79, 150, 253, 176, 90, 65, 130, 254, 106, 208, 205, 55, 238, 70, 206, 177, 11, 252, 234, 135, 249, 132, 63, 114, 21, 6, 8, 170, 62, 149, 92, 225, 0, 20, 205, 27, 103, 66, 226, 114, 87, 5, 179, 14, 3, 253, 14, 83, 39, 224, 87, 80, 125, 23, 242, 211, 54, 232, 233, 215, 187, 67, 166, 215, 60, 17, 56, 252, 199, 206, 90, 130, 245, 2, 193, 26, 152, 108, 118, 53, 69, 72, 252, 226, 243, 198, 97, 170, 119, 65, 240, 235, 194, 19, 254, 149, 22, 106, 158, 218, 237, 176, 63, 104, 194, 188, 58, 134, 242, 229, 252, 231, 114, 39, 147, 88, 219, 212, 80, 206, 7, 136, 252, 40, 145, 79, 38, 17, 231, 36, 7, 151, 159, 87, 160, 64, 238, 70, 226, 147, 192, 158, 55, 255, 55, 91, 230, 247, 34, 86, 113, 30, 1, 168, 211, 8, 206, 244, 246, 230, 122, 104, 125, 50, 71, 150, 231, 162, 55, 12, 54, 146, 80, 241, 1, 8, 163, 152, 2, 81, 63, 23, 173, 78, 137, 193, 201, 214, 161, 188, 90, 125, 214, 127, 209, 56, 145, 30, 13, 118, 74, 56, 72, 114, 243, 20, 47, 166, 125, 128, 240, 80, 195, 132, 222, 159, 91, 5, 179, 88, 19, 136, 243, 71, 16, 83, 254, 156, 14, 68, 11, 127, 48, 232, 160, 196, 151, 65, 209, 210, 9, 16, 158, 0, 97, 44, 193, 219, 164, 6, 80, 70, 103, 124, 209, 202, 50, 178, 69, 65, 131, 130, 78, 201, 206, 1, 41, 221, 245, 154, 190, 77, 50, 68, 239, 147, 123, 2, 100, 95, 230, 21, 97, 35, 231, 0, 8, 63, 247, 168, 65, 77, 203, 248, 164, 167, 208, 146, 180, 90, 161, 98, 44, 173, 211, 228, 69, 174, 117, 169, 92, 224, 164, 247, 247, 130, 126, 84, 42, 192, 83, 121, 24, 129, 144, 92, 156, 169, 197, 111, 22, 164, 90, 110, 249, 41, 75, 114, 183, 249, 247, 32, 237, 151, 178, 153, 45, 35, 111, 221, 86, 169, 42, 249, 248, 139, 157, 234, 68, 147, 45, 191, 55, 134, 4, 227, 161, 67, 83, 8, 226, 235, 75, 141, 232, 248, 124, 159, 237, 66, 189, 2, 9, 108, 83, 242, 100, 159, 100, 22, 41, 42, 48, 28, 135, 25, 141, 98, 60, 83, 32, 161, 208, 83, 18, 142, 70, 204, 163, 228, 92, 58, 194, 41, 73, 99, 228, 148, 58, 203, 189, 152, 139, 234, 20, 33, 198, 226, 132, 241, 233, 22, 98, 170, 168, 213, 167, 129, 43, 136, 244, 115, 32, 210, 24, 231, 128, 6, 73, 133, 58, 120, 98, 156, 88, 134, 49, 135, 200, 168, 132, 183, 46, 197, 233, 219, 171, 170, 115, 47, 136, 58, 34, 238, 51, 43, 143, 244, 135, 174, 78, 171, 239, 11, 249, 4, 58, 118, 5, 27, 126, 175, 163, 110, 40, 134, 40, 119, 106, 203, 88, 39, 121, 165, 172, 61, 214, 239, 130, 2, 240, 50, 83, 97, 87, 67, 243, 174, 151, 72, 122, 14, 73, 153, 54, 2, 134, 9, 1, 65, 139, 160, 127, 38, 220, 232, 157, 95, 237, 91, 44, 50, 55, 203, 102, 249, 50, 64, 134, 123, 71, 255, 204, 188, 64, 224, 179, 55, 33, 176, 146, 51, 220, 166, 6, 232, 28, 129, 171, 134, 241, 181, 208, 230, 24, 222, 200, 153, 110, 55, 135, 102, 83, 230, 230, 52, 192, 107, 152, 156, 190, 125, 239, 101, 43, 45, 163, 94, 91, 36, 218, 83, 248, 77, 158, 77, 235, 38, 61, 169, 118, 117, 52, 220, 39, 91, 164, 192, 131, 198, 153, 82, 67, 51, 119, 29, 53, 243, 195, 104, 147, 115, 228, 56, 86, 135, 205, 118, 175, 179, 75, 247, 23, 223, 245, 100, 67, 85, 22, 113, 67, 19, 237, 40, 202, 147, 3, 73, 224, 170, 75, 205, 56, 120, 56, 32, 117, 61, 148, 133, 249, 68, 66, 81, 65, 15, 24, 56, 130, 176, 124, 102, 41, 181, 26, 131, 96, 89, 3, 138, 42, 126, 4, 157, 175, 27, 30, 14, 187, 75, 124, 140, 141, 64, 102, 1, 117, 115, 194, 106, 229, 39, 3, 74, 11, 244, 210, 244, 184, 81, 137, 159, 167, 86, 94, 105, 199, 86, 245, 2, 207, 101, 235, 190, 27, 71, 181, 127, 10, 60, 211, 39, 155, 182, 59, 118, 216, 54, 61, 20, 165, 114, 139, 203, 145, 248, 205, 130, 42, 59, 8, 154, 233, 106, 227, 164, 246, 3, 36, 234, 250, 133, 173, 200, 173, 4 };
            var expectedDecrypted = new byte[1024] { 188, 72, 236, 119, 104, 111, 12, 51, 110, 35, 30, 47, 31, 10, 196, 1, 32, 13, 117, 112, 11, 219, 198, 192, 250, 57, 4, 207, 141, 209, 122, 36, 34, 5, 8, 112, 18, 188, 112, 76, 126, 151, 49, 187, 40, 119, 232, 122, 34, 134, 199, 28, 56, 57, 175, 229, 151, 200, 181, 8, 208, 194, 7, 37, 11, 196, 223, 116, 81, 140, 15, 111, 99, 175, 75, 59, 140, 202, 97, 77, 38, 127, 253, 35, 14, 174, 194, 128, 93, 223, 74, 223, 134, 218, 28, 73, 231, 138, 219, 153, 59, 174, 49, 191, 162, 8, 87, 189, 83, 77, 55, 56, 170, 234, 58, 166, 151, 181, 26, 131, 84, 66, 235, 85, 37, 167, 41, 3, 104, 215, 203, 229, 190, 4, 195, 211, 254, 105, 16, 85, 66, 90, 68, 40, 150, 27, 189, 199, 42, 56, 155, 33, 19, 210, 110, 42, 21, 135, 33, 19, 147, 70, 77, 239, 228, 164, 6, 238, 158, 33, 31, 116, 150, 162, 177, 178, 141, 23, 31, 114, 39, 251, 20, 182, 180, 255, 232, 14, 127, 112, 222, 188, 188, 51, 155, 151, 252, 202, 86, 18, 174, 101, 202, 71, 255, 180, 159, 213, 119, 118, 34, 127, 13, 94, 27, 153, 111, 84, 145, 190, 177, 123, 194, 30, 69, 155, 0, 54, 228, 223, 152, 186, 109, 116, 92, 118, 199, 180, 216, 209, 177, 38, 161, 104, 12, 201, 82, 34, 172, 154, 4, 94, 182, 30, 193, 33, 46, 18, 135, 44, 1, 153, 186, 99, 168, 121, 4, 5, 139, 131, 4, 214, 254, 62, 178, 238, 190, 182, 59, 175, 48, 208, 112, 173, 102, 221, 179, 236, 136, 233, 47, 48, 235, 12, 36, 21, 171, 150, 90, 112, 202, 91, 37, 165, 121, 209, 78, 16, 162, 171, 223, 79, 144, 69, 48, 162, 48, 5, 33, 62, 82, 70, 230, 81, 15, 122, 119, 222, 134, 134, 229, 242, 199, 47, 212, 7, 0, 208, 201, 128, 56, 180, 243, 51, 89, 52, 134, 187, 59, 22, 35, 248, 187, 220, 183, 21, 137, 103, 173, 123, 134, 6, 11, 190, 202, 129, 165, 82, 52, 46, 185, 159, 180, 167, 111, 231, 65, 105, 255, 134, 7, 104, 101, 132, 15, 146, 250, 94, 148, 72, 43, 233, 4, 63, 133, 203, 231, 56, 197, 202, 150, 136, 172, 165, 125, 5, 5, 98, 222, 180, 57, 31, 81, 225, 61, 224, 178, 62, 140, 70, 109, 251, 52, 208, 186, 61, 67, 0, 178, 32, 78, 131, 217, 140, 107, 187, 107, 7, 209, 158, 59, 147, 17, 199, 33, 103, 97, 24, 1, 17, 6, 234, 50, 76, 249, 190, 17, 123, 28, 25, 90, 203, 189, 246, 156, 188, 217, 204, 24, 40, 226, 228, 233, 198, 103, 255, 179, 65, 22, 229, 178, 161, 38, 183, 171, 176, 163, 143, 99, 218, 13, 30, 44, 178, 195, 95, 240, 126, 168, 84, 197, 191, 104, 128, 245, 35, 213, 255, 144, 103, 114, 207, 113, 62, 155, 99, 63, 80, 120, 65, 184, 95, 79, 85, 203, 114, 190, 101, 207, 63, 157, 9, 116, 66, 148, 207, 2, 30, 89, 105, 192, 6, 24, 2, 45, 121, 34, 139, 255, 68, 19, 106, 234, 99, 200, 34, 108, 217, 54, 35, 56, 39, 69, 224, 226, 41, 24, 87, 208, 106, 41, 11, 40, 65, 215, 38, 213, 195, 170, 255, 191, 33, 125, 106, 35, 243, 235, 68, 5, 72, 154, 194, 247, 183, 76, 103, 70, 205, 178, 65, 215, 45, 170, 206, 98, 106, 39, 60, 16, 148, 147, 81, 143, 154, 118, 248, 164, 192, 224, 253, 193, 165, 184, 195, 131, 123, 185, 48, 50, 29, 189, 182, 100, 80, 169, 254, 149, 138, 43, 40, 22, 191, 111, 177, 137, 65, 175, 178, 181, 187, 27, 97, 47, 156, 165, 224, 11, 56, 10, 145, 19, 218, 141, 210, 30, 145, 63, 4, 150, 149, 178, 231, 169, 177, 15, 160, 177, 163, 33, 16, 132, 88, 170, 229, 126, 30, 70, 215, 173, 187, 245, 116, 151, 86, 228, 253, 87, 244, 182, 242, 14, 159, 179, 54, 102, 157, 32, 129, 148, 140, 207, 88, 26, 19, 146, 37, 210, 97, 24, 146, 81, 240, 34, 199, 134, 95, 2, 156, 69, 161, 8, 45, 7, 206, 181, 54, 168, 36, 8, 214, 195, 160, 120, 205, 245, 16, 76, 148, 158, 230, 28, 77, 50, 99, 14, 156, 235, 221, 52, 255, 165, 196, 206, 170, 65, 168, 57, 14, 104, 204, 125, 43, 200, 197, 65, 102, 127, 122, 125, 215, 18, 231, 35, 130, 22, 234, 182, 238, 16, 210, 182, 25, 187, 96, 72, 16, 232, 86, 106, 91, 190, 125, 236, 79, 149, 164, 29, 177, 166, 200, 230, 6, 227, 59, 18, 208, 106, 114, 0, 169, 31, 173, 188, 86, 232, 93, 85, 47, 164, 212, 214, 85, 143, 79, 248, 18, 129, 105, 254, 150, 133, 12, 121, 48, 198, 14, 215, 70, 104, 255, 176, 30, 165, 56, 199, 154, 154, 90, 198, 99, 21, 39, 149, 32, 232, 213, 53, 127, 195, 123, 144, 101, 123, 193, 228, 163, 156, 91, 230, 89, 216, 173, 148, 69, 185, 51, 250, 219, 255, 198, 22, 72, 37, 173, 85, 16, 198, 167, 210, 121, 173, 53, 186, 43, 241, 245, 12, 128, 67, 52, 221, 200, 106, 162, 69, 132, 119, 194, 43, 125, 118, 152, 152, 73, 132, 19, 118, 74, 128, 180, 52, 46, 12, 104, 69, 140, 227, 229, 104, 183, 11, 73, 124, 31, 151, 162, 44, 231, 202, 7, 6, 99, 242, 183, 216, 244, 43, 175, 163, 141, 112, 202, 158, 42, 16, 54, 76, 187, 131, 90, 76, 29, 6, 83, 179, 127, 21, 209, 149, 222, 35, 51, 115, 196, 17, 167, 31, 62, 209, 218, 161, 81, 86, 163, 137, 14, 170, 175, 99, 47, 144, 224, 142, 238, 97, 221, 77, 57, 20, 14, 44, 121, 40, 59, 180, 88, 49, 74, 185, 106, 145, 128, 190, 221 };

            stream.Write(encrypted);
            var actualDecrypted = Reader.ReadAndDecryptData(stream, 0, 1052);

            Assert.True(expectedDecrypted.SequenceEqual(actualDecrypted));
        }
    }

    public abstract class VaultReaderTests<TSelf> where TSelf : VaultReaderTests<TSelf>, new()
    {
        protected abstract IVaultReader Reader { get; }
        protected abstract IVaultSession Session { get; }


        [Fact]
        public void ReadSaltReturnsCorrectValues()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version
            byte[] expectedSalt = RandomNumberGenerator.GetBytes(Reader.SaltSize);
            stream.Write(expectedSalt);

            var actualSalt = Reader.ReadSalt(stream);

            Assert.True(expectedSalt.SequenceEqual(actualSalt));
        }

        [Fact]
        public void ReadSaltThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.ReadSalt(null!));
        }

        [Fact]
        public void ReadIterationsNumberReturnsCorrectNumber()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version;
            stream.Write(new byte[Reader.SaltSize]);
            int expectedIterations = RandomNumberGenerator.GetInt32(int.MaxValue);
            byte[] iterationsBytes = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(iterationsBytes, expectedIterations);
            stream.Write(iterationsBytes);

            int actualIterations = Reader.ReadIterationsNumber(stream);

            Assert.Equal(expectedIterations, actualIterations);
        }

        [Fact]
        public void ReadIterationsNumberThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.ReadIterationsNumber(null!));
        }

        [Fact]
        public void PrepareVaultHeaderReturnsCorrectValues()
        {
            byte[] expectedSalt = RandomNumberGenerator.GetBytes(Reader.SaltSize);
            int expectedIterations = RandomNumberGenerator.GetInt32(int.MaxValue);

            byte[] actualHeader = Reader.PrepareVaultHeader(expectedSalt, expectedIterations);

            Assert.Equal(Reader.Version, actualHeader[0]);
            Assert.True(expectedSalt.SequenceEqual(actualHeader[1..(Reader.SaltSize + 1)])); //+1 because end index is exclusive
            Assert.Equal(expectedIterations, BinaryPrimitives.ReadInt32LittleEndian(actualHeader[^4..]));
        }

        [Fact]
        public void PrepareVaultHeaderThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.PrepareVaultHeader(null!, 1));
        }

        [Fact]
        public void PrepareVaultHeaderThrowsForNegativeValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Reader.PrepareVaultHeader(new byte[0], -1));
        }

        [Fact]
        public void PrepareVaultHeaderThrowsForZeroValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Reader.PrepareVaultHeader(new byte[0], 0));
        }

        [Fact]
        public void ReadMetadataOffsetsReturnsCorrectValues()
        {
            var stream = new MemoryStream();
            stream.WriteByte(0); //First byte is the vault version;
            stream.Write(new byte[Reader.SaltSize]);
            stream.Write(new byte[4]); //Iterations number for password as int
            //Prepare offsets and save to stream
            ushort fileCount = (ushort)RandomNumberGenerator.GetInt32(100);
            long[] expectedOffsets = new long[fileCount];
            for (int i = 0; i < fileCount; i++)
            {
                expectedOffsets[i] = RandomNumberGenerator.GetInt32(int.MaxValue);
            }
            Reader.SaveMetadataOffsets(stream, expectedOffsets);

            long[] actualOffsets = Reader.ReadMetadataOffsets(stream);

            Assert.True(expectedOffsets.SequenceEqual(actualOffsets));

        }

        [Fact]
        public void ReadMetadataOffsetsThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.ReadMetadataOffsets(null!));
        }

        [Fact]
        public void ReadAndDecryptDataThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => Reader.ReadAndDecryptData(null!, 1, 1));
        }

        [Fact]
        public void ReadAndDecryptDataThrowsForNegativeValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Reader.ReadAndDecryptData(new MemoryStream(), -1, 1));
            Assert.Throws<ArgumentOutOfRangeException>(() => Reader.ReadAndDecryptData(new MemoryStream(), 1, -1));
        }

        [Fact]
        public void ReadAndDecryptDataThrowsForZeroValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Reader.ReadAndDecryptData(new MemoryStream(), 1, 0));
        }

        [Fact]
        public void ReadAndDecryptDataThrowsForInvalidValues()
        {
            //Setup to prevent EndOfStreamException
            var stream = new MemoryStream();
            stream.Write(RandomNumberGenerator.GetBytes(32));
            Assert.Throws<ArgumentException>(() => Reader.ReadAndDecryptData(stream, 1, 1));
        }

        [Fact]
        public void VaultEncryptionThrowsForInvalidValues()
        {
            Assert.Throws<ArgumentException>(() => Reader.VaultEncryption(null));
            Assert.Throws<ArgumentException>(() => Reader.VaultEncryption(new byte[0]));
        }


        [Fact]
        public void ReaderWritesAndReadsHeaderCorrectly()
        {
            var stream = new MemoryStream();
            byte[] expectedSalt = RandomNumberGenerator.GetBytes(Reader.SaltSize);
            int expectedIterations = RandomNumberGenerator.GetInt32(int.MaxValue);
            
            stream.Write(Reader.PrepareVaultHeader(expectedSalt, expectedIterations));

            byte[] actualSalt = Reader.ReadSalt(stream);
            int actualIterations = Reader.ReadIterationsNumber(stream);

            Assert.True(expectedSalt.SequenceEqual(actualSalt));
            Assert.Equal(expectedIterations, actualIterations);
        }

        [Fact]
        public void VaultEncryptionAndVaultDecryptionWorkCorrectly()
        {
            var stream = new MemoryStream();
            //Fill the beginning of stream with random values to simulate actual stream, random length can be set to 0
            int randomOffset = RandomNumberGenerator.GetInt32(1000);
            for (int i = 0; i < randomOffset; i++)
            {
                stream.WriteByte((byte)RandomNumberGenerator.GetInt32(byte.MaxValue));
            }
            int randomLength = RandomNumberGenerator.GetInt32(1, 1000); //Random size of the data to encrypt
            byte[] expectedDecrypted = new byte[randomLength];
            for (int i = 0; i < randomLength; i++)
            {
                expectedDecrypted[i] = (byte)RandomNumberGenerator.GetInt32(byte.MaxValue);
            }
            byte[] actualEncrypted = Reader.VaultEncryption(expectedDecrypted);
            stream.Write(actualEncrypted);
            //Fill the end of the stream with random values to simulate actual stream, random length can be set to 0
            int randomSuffixLength = RandomNumberGenerator.GetInt32(1000);
            for (int i = 0; i < randomSuffixLength; i++)
            {
                stream.WriteByte((byte)RandomNumberGenerator.GetInt32(byte.MaxValue));
            }

            byte[] actualDecrypted = Reader.ReadAndDecryptData(stream, randomOffset, actualEncrypted.Length);
        }
    }
}
