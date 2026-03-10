using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;
using static VaultCrypt.EncryptionOptions;

namespace VaultCrypt.Tests.Services
{
    public class EncryptionOptionsServiceTests
    {
        private readonly VaultCrypt.Services.EncryptionOptionsService _service;
        private readonly VaultSession _vaultSession;

        public EncryptionOptionsServiceTests()
        {
            _vaultSession = TestsHelper.CreateFilledSessionInstanceWithReader();
            _service = new VaultCrypt.Services.EncryptionOptionsService(_vaultSession);
        }

        [Fact]
        void PrepareEncryptionOptionsReturnsCorrectInformation()
        {
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(32));
            var encryptionAlgorithm = EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value;
            
            var actualOptions = _service.PrepareEncryptionOptions(fileInfo, encryptionAlgorithm, 1);

            Assert.Equal(0, actualOptions.Version);
            Assert.Equal(Encoding.UTF8.GetBytes(fileInfo.Name), actualOptions.FileName);
            Assert.Equal(32UL + (ulong)encryptionAlgorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize, actualOptions.FileSize);
            Assert.Equal(encryptionAlgorithm.ID, actualOptions.EncryptionAlgorithm);
            Assert.False(actualOptions.IsChunked);
            Assert.Null(actualOptions.ChunkInformation);

            fileInfo.Delete();
        }

        [Fact]
        void PrepareEncryptionOptionsReturnsCorrectInformationChunked()
        {
            int fileSize = 1024 * 1024 + 3; //1MB + 3 bytes (1 048 579 bytes)
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(fileSize)); 
            var encryptionAlgorithm = EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value;

            var actualOptions = _service.PrepareEncryptionOptions(fileInfo, encryptionAlgorithm, 1);

            Assert.Equal(0, actualOptions.Version);
            Assert.Equal(Encoding.UTF8.GetBytes(fileInfo.Name), actualOptions.FileName);
            Assert.Equal((ulong)(fileSize + (encryptionAlgorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize * actualOptions.ChunkInformation!.TotalChunks)), actualOptions.FileSize);
            Assert.Equal(encryptionAlgorithm.ID, actualOptions.EncryptionAlgorithm);
            Assert.True(actualOptions.IsChunked);
            Assert.Equal(1, actualOptions.ChunkInformation!.ChunkSize);
            Assert.Equal(2, actualOptions.ChunkInformation!.TotalChunks);
            Assert.Equal(3U, actualOptions.ChunkInformation!.FinalChunkSize);

            fileInfo.Delete();
        }

        [Fact]
        void PrepareEncryptionOptionsThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.PrepareEncryptionOptions(null!, EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value, 1));
        }

        [Fact]
        void PrepareEncryptionOptionsThrowsForZeroValues()
        {
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(0));
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.PrepareEncryptionOptions(fileInfo, EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value, 0));
            fileInfo.Delete();
        }

        [Fact]
        void EncryptAndPadFileEncryptionOptionsReturnsCorrectInformation()
        {
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(32));
            var encryptionAlgorithm = EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value;
            var options = _service.PrepareEncryptionOptions(fileInfo, encryptionAlgorithm, 1);

            var encrypted = _service.EncryptAndPadFileEncryptionOptions(options);

            Assert.Equal(_vaultSession.VAULT_READER.EncryptionOptionsSize, encrypted.Length);
            Assert.False(encrypted.SequenceEqual(new byte[_vaultSession.VAULT_READER.EncryptionOptionsSize]));

            fileInfo.Delete();
        }

        [Fact]
        void EncryptAndPadFileEncryptionOptionsThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.EncryptAndPadFileEncryptionOptions(null!));
        }

        [Fact]
        void EncryptAndPadFileEncryptionOptionsThrowsForTooBigOptions()
        {
            var options = new EncryptionOptions.FileEncryptionOptions(0, new byte[_vaultSession.VAULT_READER.EncryptionOptionsSize + 1], 1, EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value.ID, false, null);

            Assert.Throws<VaultException>(() => _service.EncryptAndPadFileEncryptionOptions(options));
        }

        [Fact]
        void GetDecryptedFileEncryptionOptionsDecryptsCorrectly()
        {
            var stream = new MemoryStream();
            stream.Write(RandomNumberGenerator.GetBytes(10)); //Writing to stream to ensure the method works despite the stream holding more data
            //Precomputed value 
            byte[] encrypted = new byte[1024] { 180, 161, 139, 229, 235, 241, 147, 215, 113, 181, 69, 147, 77, 66, 141, 172, 209, 36, 70, 74, 27, 64, 0, 180, 199, 249, 18, 217, 172, 230, 61, 163, 37, 197, 203, 15, 240, 60, 222, 179, 45, 109, 97, 106, 241, 42, 181, 62, 37, 240, 171, 153, 239, 225, 224, 111, 192, 13, 15, 255, 54, 90, 218, 167, 241, 157, 36, 130, 208, 87, 175, 232, 96, 51, 101, 84, 21, 175, 216, 85, 61, 31, 126, 200, 155, 103, 146, 242, 13, 61, 1, 150, 84, 254, 100, 226, 131, 199, 192, 167, 214, 152, 177, 101, 244, 39, 9, 42, 61, 147, 0, 21, 234, 158, 99, 237, 143, 127, 63, 196, 158, 76, 252, 116, 33, 83, 174, 176, 203, 97, 38, 58, 164, 205, 68, 140, 130, 40, 1, 195, 219, 85, 117, 96, 195, 101, 157, 246, 82, 165, 96, 52, 52, 139, 19, 136, 54, 198, 55, 160, 226, 5, 30, 154, 11, 101, 174, 75, 158, 42, 116, 26, 76, 183, 203, 163, 119, 146, 19, 229, 161, 27, 169, 8, 66, 224, 131, 213, 52, 53, 109, 87, 227, 114, 198, 166, 115, 117, 226, 231, 216, 21, 241, 247, 49, 86, 56, 242, 79, 75, 81, 116, 99, 166, 189, 161, 151, 74, 165, 247, 188, 198, 77, 90, 188, 150, 79, 23, 19, 44, 42, 214, 242, 208, 71, 121, 188, 113, 65, 79, 252, 92, 181, 36, 170, 50, 179, 20, 167, 172, 207, 9, 225, 167, 152, 246, 137, 57, 143, 31, 211, 199, 145, 20, 66, 182, 24, 73, 254, 231, 176, 75, 129, 140, 18, 252, 49, 195, 77, 0, 49, 145, 61, 0, 121, 225, 160, 243, 163, 208, 173, 72, 137, 5, 168, 220, 72, 115, 5, 181, 249, 114, 184, 96, 77, 5, 80, 140, 7, 143, 231, 201, 165, 35, 143, 141, 158, 221, 165, 15, 173, 14, 114, 64, 73, 117, 185, 77, 123, 22, 197, 77, 160, 109, 9, 120, 4, 212, 184, 45, 243, 167, 187, 131, 224, 8, 145, 73, 249, 5, 84, 254, 23, 189, 151, 72, 37, 13, 52, 181, 116, 241, 4, 172, 148, 194, 169, 249, 135, 95, 165, 248, 134, 217, 46, 218, 109, 241, 79, 120, 40, 80, 219, 0, 113, 254, 13, 228, 166, 101, 116, 152, 48, 128, 121, 108, 98, 154, 32, 105, 196, 154, 233, 153, 222, 222, 123, 246, 59, 64, 7, 189, 237, 199, 45, 167, 90, 253, 31, 94, 222, 228, 34, 224, 70, 154, 245, 253, 213, 239, 247, 234, 44, 102, 112, 162, 240, 245, 110, 61, 255, 105, 57, 250, 27, 12, 247, 220, 4, 63, 210, 124, 2, 168, 173, 74, 3, 62, 135, 52, 109, 78, 118, 190, 122, 57, 144, 64, 188, 156, 106, 29, 197, 111, 54, 83, 74, 221, 22, 35, 29, 44, 48, 95, 224, 247, 172, 244, 143, 31, 122, 148, 167, 195, 142, 56, 27, 226, 96, 137, 118, 161, 248, 198, 199, 222, 218, 3, 153, 232, 219, 109, 166, 68, 4, 69, 48, 192, 109, 176, 30, 85, 158, 75, 243, 78, 167, 137, 113, 130, 224, 127, 34, 246, 114, 80, 103, 155, 192, 30, 228, 182, 145, 41, 211, 207, 243, 133, 122, 146, 35, 51, 10, 46, 174, 184, 42, 138, 106, 136, 6, 46, 9, 137, 76, 97, 136, 110, 215, 188, 22, 39, 163, 18, 164, 170, 23, 82, 215, 14, 205, 145, 84, 213, 44, 96, 118, 110, 44, 55, 40, 30, 30, 52, 253, 176, 78, 137, 199, 96, 170, 150, 151, 113, 30, 241, 131, 134, 56, 187, 127, 80, 73, 206, 2, 205, 99, 91, 63, 95, 37, 31, 28, 82, 125, 57, 160, 69, 140, 192, 182, 51, 234, 106, 130, 113, 152, 5, 134, 181, 13, 174, 101, 4, 82, 220, 63, 185, 244, 240, 100, 71, 188, 171, 157, 90, 163, 33, 226, 209, 158, 149, 51, 250, 65, 147, 26, 106, 247, 121, 200, 75, 102, 47, 13, 255, 207, 189, 12, 187, 11, 200, 243, 56, 152, 127, 32, 85, 102, 228, 161, 120, 34, 249, 111, 254, 86, 133, 140, 168, 159, 11, 155, 23, 26, 90, 203, 233, 44, 190, 16, 27, 175, 223, 45, 51, 95, 241, 8, 23, 14, 21, 153, 227, 108, 245, 27, 236, 3, 85, 99, 0, 21, 248, 6, 242, 6, 116, 50, 11, 112, 152, 24, 196, 76, 56, 54, 61, 74, 230, 15, 27, 2, 133, 93, 42, 87, 164, 26, 193, 234, 165, 139, 151, 77, 167, 119, 227, 254, 226, 251, 254, 169, 63, 253, 17, 189, 184, 11, 24, 5, 109, 168, 103, 118, 117, 112, 120, 202, 208, 233, 113, 81, 140, 209, 184, 138, 209, 247, 32, 70, 36, 90, 59, 168, 184, 8, 164, 42, 171, 123, 158, 116, 41, 105, 40, 77, 73, 118, 157, 204, 72, 3, 47, 235, 136, 249, 28, 58, 142, 254, 94, 169, 28, 19, 221, 204, 162, 222, 59, 122, 37, 51, 135, 144, 134, 190, 1, 95, 183, 233, 145, 177, 218, 110, 166, 86, 179, 47, 186, 105, 112, 179, 44, 81, 238, 51, 83, 119, 42, 181, 253, 193, 74, 151, 243, 230, 251, 65, 19, 74, 30, 41, 31, 163, 124, 150, 1, 73, 218, 208, 62, 0, 180, 93, 45, 63, 49, 122, 79, 231, 151, 17, 96, 145, 246, 28, 49, 128, 248, 97, 26, 150, 55, 237, 185, 174, 253, 45, 198, 237, 68, 233, 208, 129, 204, 53, 138, 98, 36, 248, 237, 246, 8, 210, 133, 146, 214, 199, 186, 108, 15, 223, 20, 73, 215, 64, 191, 77, 253, 75, 112, 89, 71, 142, 81, 90, 205, 207, 163, 36, 85, 166, 50, 202, 50, 106, 64, 96, 162, 210, 232, 10, 196, 246, 83, 249, 128, 70, 184, 30, 85, 146, 209, 196, 149, 115, 68, 21, 87, 21, 19, 134, 202, 141, 11, 131, 177, 68, 151, 27, 241, 239, 239, 185, 49, 98, 106, 89, 232, 250, 138, 24, 78, 231, 78, 21, 225, 110, 79, 254, 177, 87, 172 };
            stream.Write(encrypted);
            FileEncryptionOptions expected = new FileEncryptionOptions(0, new byte[13] { 116, 109, 112, 99, 103, 103, 99, 98, 105, 46, 116, 109, 112 }, 60, 0, false, null); //FileName = tmpcggcbi.tmp

            var actual = _service.GetDecryptedFileEncryptionOptions(stream, 10);

            Assert.Equal(expected, actual);
        }

        [Fact]
        void GetDecryptedFileEncryptionOptionsThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.GetDecryptedFileEncryptionOptions(null!, 0));
        }

        [Fact]
        void GetDecryptedFileEncryptionOptionsThrowsForNegativeValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.GetDecryptedFileEncryptionOptions(new MemoryStream(), -1));
        }


        [Fact]
        void PrepareEncryptionOptionsThenEncryptThenDecryptSuccessfully()
        {
            //Create temporary file with random data with size of 1-1024bytes
            var fileInfo = new FileInfo(TestsHelper.CreateTemporaryFile(RandomNumberGenerator.GetInt32(1, 1024)));
            var encryptionAlgorithm = EncryptionAlgorithm.GetEncryptionAlgorithmInfo.First().Value;
            var options = _service.PrepareEncryptionOptions(fileInfo, encryptionAlgorithm, 1);

            var encrypted = _service.EncryptAndPadFileEncryptionOptions(options);

            //Create stream with other random data to simulate actual vault
            var stream = new MemoryStream();
            int randomNumber = RandomNumberGenerator.GetInt32(1024);
            stream.Write(RandomNumberGenerator.GetBytes(randomNumber));
            stream.Write(encrypted);
            //Append extra data at the end to mimick actual vault
            stream.Write(RandomNumberGenerator.GetBytes(10));


            var result = _service.GetDecryptedFileEncryptionOptions(stream, randomNumber);

            Assert.Equal(options, result);

            fileInfo.Delete();
        }


    }
}
