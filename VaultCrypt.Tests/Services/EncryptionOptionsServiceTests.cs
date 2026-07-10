using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt.Tests.Services
{
    public class EncryptionOptionsServiceTests
    {
        private readonly VaultCrypt.Services.EncryptionOptionsService _service = new VaultCrypt.Services.EncryptionOptionsService();

        [Theory]
        [MemberData(nameof(TestsHelper.EncryptionAlgorithms), MemberType = typeof(TestsHelper))]
        internal void PrepareEncryptionOptionsReturnsCorrectInformation(EncryptionAlgorithm.EncryptionAlgorithmInfo encryptionAlgorithm)
        {
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(32));
            try
            {
                using (var actualOptions = _service.PrepareEncryptionOptions(fileInfo, encryptionAlgorithm, 1))
                {
                    Assert.Equal(VaultCrypt.Services.EncryptionOptionsService.NewestFileEncryptionOptions, actualOptions.Version);
                    Assert.Equal(fileInfo.Name, actualOptions.GetFileName());
                    Assert.Equal(32UL + (ulong)encryptionAlgorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize, actualOptions.FileSize);
                    Assert.Equal(encryptionAlgorithm.ID, actualOptions.EncryptionAlgorithm);
                    Assert.False(actualOptions.IsChunked);
                    Assert.Null(actualOptions.ChunkInformation);
                }
            }
            finally
            {
                fileInfo.Delete();
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.EncryptionAlgorithms), MemberType = typeof(TestsHelper))]
        internal void PrepareEncryptionOptionsReturnsCorrectInformationChunked(EncryptionAlgorithm.EncryptionAlgorithmInfo encryptionAlgorithm)
        {
            int fileSize = 1024 * 1024 + 3; //1MB + 3 bytes (1 048 579 bytes)
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(fileSize));
            try
            {

                using (var actualOptions = _service.PrepareEncryptionOptions(fileInfo, encryptionAlgorithm, 1))
                {
                    Assert.Equal(VaultCrypt.Services.EncryptionOptionsService.NewestFileEncryptionOptions, actualOptions.Version);
                    Assert.Equal(fileInfo.Name, actualOptions.GetFileName());
                    Assert.Equal(((ulong)fileSize + ((ulong)encryptionAlgorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize * actualOptions.ChunkInformation!.TotalChunks)), actualOptions.FileSize);
                    Assert.Equal(encryptionAlgorithm.ID, actualOptions.EncryptionAlgorithm);
                    Assert.True(actualOptions.IsChunked);
                    Assert.Equal(1, actualOptions.ChunkInformation!.ChunkSize);
                    Assert.Equal(2UL, actualOptions.ChunkInformation!.TotalChunks);
                    Assert.Equal(3U, actualOptions.ChunkInformation!.FinalChunkSize);
                }
            }
            finally
            {
                fileInfo.Delete();
            }
        }

        [Fact]
        internal void PrepareEncryptionOptionsThrowsForInvalidFileInfo()
        {
            Assert.Throws<ArgumentNullException>(() => _service.PrepareEncryptionOptions(null!, EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value, 1));
        }

        [Fact]
        internal void PrepareEncryptionOptionsThrowsForInvalidAlgorithm()
        {
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(0));
            try
            {
                Assert.Throws<ArgumentNullException>(() => _service.PrepareEncryptionOptions(fileInfo, null!, 1));
            }
            finally
            {
                fileInfo.Delete();
            }
        }

        [Theory]
        [InlineData(0)]
        internal void PrepareEncryptionOptionsThrowsForInvalidChunkSize(ushort chunkSize)
        {
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(0));
            try
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => _service.PrepareEncryptionOptions(fileInfo, EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value, chunkSize));
            }
            finally
            {
                fileInfo.Delete();
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.EncryptionAlgorithms), MemberType = typeof(TestsHelper))]
        internal void EncryptAndPadFileEncryptionOptionsReturnsCorrectSize(EncryptionAlgorithm.EncryptionAlgorithmInfo encryptionAlgorithm)
        {
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(32));
            try
            {
                using var options = _service.PrepareEncryptionOptions(fileInfo, encryptionAlgorithm, 1);
                using var encrypted = _service.PadAndEncryptFileEncryptionOptions(options);

                Assert.Equal(TestsHelper.GetNewestReader.EncryptionOptionsSize, encrypted.AsSpan.Length);
                Assert.False(encrypted.AsSpan.IndexOfAnyExcept((byte)0) == -1);
            }
            finally
            {
                fileInfo.Delete();
            }
        }

        [Fact]
        internal void EncryptAndPadFileEncryptionOptionsThrowsForInvalidOptions()
        {
            Assert.Throws<ArgumentNullException>(() => _service.PadAndEncryptFileEncryptionOptions(null!));
        }

        //Seperate test due to unmanaged memory behaviour
        [Fact]
        internal void EncryptAndPadFileEncryptionOptionsThrowsForTooBigOptions()
        {
            using ISecureBuffer tooBigFileName = SecureBuffer.Create(TestsHelper.GetNewestReader.EncryptionOptionsSize + 1);
            using var options = new EncryptionOptions.FileEncryptionOptions(0, tooBigFileName, 1, EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value.ID, false, null);

            Assert.Throws<VaultEncryptionOptionsOperationException>(() => _service.PadAndEncryptFileEncryptionOptions(options));
        }

        [Fact]
        internal void GetDecryptedFileEncryptionOptionsDecryptsCorrectly()
        {
            VaultSession.CurrentSession = TestsHelper.EmptyVaultV0Information.VaultSession; //Setting correct session to ensure decryption key matches

            var stream = new MemoryStream();
            stream.Write(RandomNumberGenerator.GetBytes(5000)); //Writing to stream to ensure the method works despite the stream holding more data
            //Precomputed value 
            byte[] encrypted = new byte[1024] { 71, 13, 170, 35, 158, 234, 197, 31, 213, 209, 30, 157, 185, 49, 199, 154, 206, 119, 161, 85, 75, 80, 207, 237, 159, 243, 239, 203, 246, 218, 170, 13, 232, 140, 249, 246, 35, 6, 90, 147, 175, 13, 135, 121, 214, 6, 72, 232, 8, 106, 15, 202, 28, 209, 32, 132, 235, 29, 115, 118, 62, 131, 227, 245, 198, 196, 128, 234, 176, 84, 154, 82, 214, 209, 39, 221, 186, 126, 125, 109, 177, 94, 76, 66, 55, 123, 186, 213, 61, 191, 171, 209, 95, 1, 167, 145, 177, 126, 116, 224, 167, 29, 107, 53, 116, 70, 198, 197, 59, 174, 218, 159, 16, 239, 240, 15, 159, 244, 163, 207, 191, 153, 134, 39, 225, 14, 78, 247, 83, 212, 21, 176, 18, 241, 219, 177, 141, 107, 171, 160, 169, 32, 252, 246, 27, 162, 73, 198, 21, 195, 71, 81, 85, 149, 63, 14, 146, 226, 69, 221, 200, 23, 212, 64, 190, 100, 71, 29, 4, 214, 177, 47, 178, 96, 183, 142, 48, 143, 194, 249, 16, 56, 77, 68, 22, 9, 15, 183, 253, 186, 46, 228, 162, 75, 8, 166, 77, 184, 165, 85, 224, 159, 207, 43, 157, 101, 90, 122, 68, 228, 226, 118, 161, 155, 207, 233, 163, 216, 210, 50, 134, 35, 139, 221, 182, 22, 42, 234, 192, 172, 235, 118, 30, 1, 28, 27, 105, 121, 160, 63, 20, 117, 46, 190, 53, 163, 152, 200, 130, 159, 109, 58, 33, 225, 199, 189, 211, 67, 226, 232, 64, 139, 176, 253, 87, 105, 222, 52, 84, 138, 155, 171, 24, 129, 169, 84, 83, 199, 242, 11, 168, 72, 246, 11, 26, 183, 250, 32, 175, 146, 44, 135, 191, 201, 39, 103, 68, 163, 67, 167, 190, 229, 188, 52, 138, 223, 131, 48, 236, 130, 209, 38, 63, 64, 189, 83, 154, 115, 86, 36, 71, 198, 127, 69, 113, 222, 131, 56, 167, 102, 139, 202, 215, 132, 157, 157, 224, 159, 33, 97, 3, 224, 186, 203, 113, 50, 59, 22, 37, 73, 63, 105, 46, 162, 108, 4, 53, 74, 239, 103, 147, 65, 177, 193, 194, 143, 214, 78, 70, 48, 185, 73, 139, 154, 88, 144, 164, 255, 190, 160, 93, 230, 64, 48, 137, 141, 152, 81, 207, 209, 30, 163, 179, 249, 182, 180, 134, 43, 55, 208, 97, 225, 224, 92, 197, 179, 17, 100, 162, 100, 40, 106, 216, 93, 17, 127, 243, 64, 128, 194, 54, 138, 183, 214, 226, 61, 199, 110, 200, 252, 2, 13, 142, 190, 54, 185, 66, 30, 66, 217, 140, 99, 41, 174, 187, 51, 85, 28, 136, 228, 60, 39, 113, 11, 66, 209, 122, 59, 85, 112, 158, 84, 73, 27, 155, 226, 168, 73, 233, 198, 67, 120, 243, 246, 228, 94, 207, 152, 153, 75, 161, 165, 137, 220, 163, 29, 186, 211, 9, 78, 60, 147, 217, 154, 96, 141, 144, 80, 113, 11, 74, 208, 206, 48, 95, 59, 176, 42, 155, 169, 184, 212, 224, 217, 94, 221, 112, 79, 191, 5, 113, 207, 86, 93, 74, 78, 79, 4, 120, 254, 63, 130, 113, 234, 237, 97, 61, 57, 203, 227, 212, 227, 181, 191, 185, 8, 240, 210, 71, 100, 177, 137, 109, 194, 120, 255, 161, 218, 223, 201, 4, 123, 220, 87, 64, 199, 61, 100, 180, 33, 71, 185, 104, 239, 141, 107, 181, 134, 69, 192, 141, 28, 190, 202, 0, 40, 153, 213, 58, 61, 105, 61, 230, 178, 9, 241, 255, 39, 132, 234, 45, 212, 47, 251, 207, 103, 143, 104, 230, 57, 40, 182, 136, 169, 196, 144, 141, 71, 129, 214, 192, 66, 140, 190, 15, 225, 45, 82, 250, 112, 231, 2, 149, 112, 185, 106, 230, 191, 76, 219, 222, 157, 190, 248, 169, 69, 44, 123, 1, 252, 193, 194, 65, 53, 46, 12, 133, 195, 137, 194, 238, 153, 209, 11, 141, 65, 49, 69, 27, 128, 222, 162, 251, 248, 212, 249, 93, 98, 61, 196, 146, 3, 69, 188, 236, 185, 76, 111, 160, 187, 117, 172, 48, 82, 21, 111, 18, 202, 217, 41, 124, 177, 35, 66, 218, 166, 226, 23, 54, 206, 35, 173, 21, 104, 213, 203, 133, 17, 115, 17, 171, 128, 13, 63, 204, 66, 11, 140, 6, 220, 188, 237, 59, 235, 18, 254, 143, 137, 172, 30, 142, 65, 161, 153, 45, 196, 37, 57, 54, 15, 121, 161, 208, 69, 27, 180, 95, 213, 213, 230, 25, 141, 136, 34, 8, 158, 25, 255, 110, 42, 106, 212, 126, 85, 203, 199, 104, 39, 41, 40, 30, 147, 71, 176, 122, 1, 36, 131, 24, 238, 213, 71, 32, 161, 94, 23, 116, 197, 42, 57, 19, 110, 107, 67, 149, 66, 115, 36, 51, 76, 23, 80, 110, 131, 102, 111, 239, 207, 175, 153, 46, 192, 21, 201, 155, 67, 235, 110, 51, 32, 213, 1, 121, 160, 59, 140, 54, 148, 144, 213, 123, 170, 240, 16, 122, 220, 146, 8, 96, 162, 161, 166, 143, 133, 177, 146, 215, 128, 73, 220, 73, 229, 38, 142, 68, 223, 176, 5, 220, 167, 63, 225, 171, 214, 51, 93, 123, 142, 84, 252, 108, 123, 49, 62, 167, 148, 121, 3, 207, 57, 54, 96, 15, 7, 49, 226, 118, 169, 89, 14, 40, 20, 227, 228, 223, 187, 243, 188, 235, 200, 139, 2, 108, 214, 18, 93, 176, 170, 226, 159, 116, 125, 114, 49, 72, 196, 193, 133, 236, 205, 82, 248, 128, 152, 60, 28, 250, 245, 106, 130, 228, 183, 239, 142, 147, 26, 76, 9, 22, 154, 150, 204, 214, 175, 173, 158, 36, 167, 18, 100, 218, 145, 70, 187, 94, 137, 76, 29, 70, 225, 231, 103, 116, 44, 124, 123, 55, 151, 48, 130, 165, 44, 72, 250, 27, 243, 236, 172, 32, 245, 150, 21, 61, 225, 105, 166, 148, 146, 93, 19, 216, 221, 195, 59, 253, 59, 62, 250, 42, 54, 31, 226, 38, 206, 153, 232, 171, 116, 52, 202, 104, 201, 97, 70 };
            stream.Write(encrypted);
            using ISecureBuffer expectedFileName = SecureBuffer.Create(13);
            new byte[13] { 116, 109, 112, 99, 103, 103, 99, 98, 105, 46, 116, 109, 112 }.CopyTo(expectedFileName.AsSpan); //FileName = tmpcggcbi.tmp
            using EncryptionOptions.FileEncryptionOptions expected = new EncryptionOptions.FileEncryptionOptions(0, expectedFileName, 60, 0, false, null);
            using var actual = _service.GetDecryptedFileEncryptionOptions(stream, 5000);

            Assert.Equal(expected, actual);
        }

        [Fact]
        internal void GetDecryptedFileEncryptionOptionsThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => _service.GetDecryptedFileEncryptionOptions(null!, 0));
        }

        [Theory]
        [InlineData(long.MinValue)]
        [InlineData(4163 - 1)] //V0 Vault header size - 1

        internal void GetDecryptedFileEncryptionOptionsThrowsForInvalidOffset(long offset)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.GetDecryptedFileEncryptionOptions(new MemoryStream(), offset));
        }


        [Theory]
        [MemberData(nameof(TestsHelper.EncryptionAlgorithms), MemberType = typeof(TestsHelper))]
        internal void PrepareEncryptionOptionsThenEncryptThenDecryptSuccessfully(EncryptionAlgorithm.EncryptionAlgorithmInfo encryptionAlgorithm)
        {
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(1000));
            try
            {
                using var options = _service.PrepareEncryptionOptions(fileInfo, encryptionAlgorithm, 1);
                using (ISecureBuffer encrypted = _service.PadAndEncryptFileEncryptionOptions(options))
                {
                    //Create stream with other random data to simulate actual vault
                    var stream = new MemoryStream();
                    int offsetToEncryptedFile = 5000;
                    stream.Write(RandomNumberGenerator.GetBytes(offsetToEncryptedFile));
                    stream.Write(encrypted.AsSpan);
                    //Append extra data at the end to mimick actual vault
                    stream.Write(RandomNumberGenerator.GetBytes(10));

                    using (var result = _service.GetDecryptedFileEncryptionOptions(stream, offsetToEncryptedFile))
                    {
                        Assert.Equal(options, result);
                    }
                }
            }
            finally
            {
                fileInfo.Delete();
            }
        }
    }
}
