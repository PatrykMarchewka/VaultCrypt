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
            byte[] encrypted = new byte[1024] { 187,139,168,54,198,217,9,132,186,56,89,4,72,140,218,29,236,237,214,50,161,171,151,250,189,183,159,52,189,145,162,109,93,117,45,68,109,223,104,19,165,172,98,228,4,32,246,123,29,86,171,99,31,230,102,166,225,179,47,90,79,61,18,81,236,27,112,220,42,246,208,170,229,250,218,163,199,132,112,213,142,223,220,37,121,132,52,109,35,81,77,147,239,82,213,199,245,109,244,211,181,89,152,241,26,75,82,120,57,167,5,81,209,92,216,252,157,186,185,243,165,194,247,150,210,184,91,31,138,70,249,245,51,81,197,233,31,230,201,146,77,188,143,95,182,252,17,201,118,92,99,70,80,168,109,126,159,177,140,54,252,99,121,13,253,63,213,127,143,84,136,75,112,146,244,10,137,96,232,226,44,129,44,219,248,134,217,94,231,254,19,214,95,208,242,116,69,224,11,220,101,35,249,71,8,230,44,23,125,197,72,110,165,239,188,1,54,85,14,66,177,126,205,99,178,214,84,96,99,97,161,107,18,68,62,161,75,204,251,156,7,239,19,31,226,39,108,170,72,233,39,215,177,27,62,30,119,251,214,87,98,158,64,78,165,104,125,115,106,101,9,232,194,142,93,110,226,48,234,233,217,8,133,87,157,142,203,250,247,96,37,202,190,183,238,127,136,78,172,60,84,232,174,18,91,95,177,246,227,185,124,9,87,2,149,153,208,186,199,18,209,239,247,223,126,111,39,83,85,72,202,151,130,167,226,127,85,111,220,241,147,213,151,81,157,177,122,185,246,108,36,137,225,140,250,57,77,82,223,149,138,74,39,61,219,14,220,247,199,23,216,34,160,197,247,223,248,144,176,54,113,135,83,159,152,217,129,203,101,146,109,240,22,179,125,221,236,76,82,69,51,162,38,123,176,105,28,70,252,74,47,39,63,67,104,131,54,76,154,14,166,61,134,219,251,216,127,11,101,29,67,26,39,148,7,27,231,18,52,115,188,23,231,197,86,178,200,52,52,55,126,233,242,229,204,222,252,193,125,12,232,90,115,139,138,230,153,62,161,5,19,11,51,19,99,48,55,22,1,72,120,17,160,225,173,189,213,94,114,67,124,29,11,120,244,151,70,154,138,69,122,232,10,204,186,147,242,74,201,175,212,197,74,229,123,7,89,63,218,135,16,181,81,170,28,183,108,27,145,161,173,241,165,18,177,31,163,118,58,18,115,159,178,134,36,63,162,40,199,237,77,54,17,183,106,204,236,45,207,111,150,172,165,65,36,241,19,24,52,79,71,5,244,135,145,86,5,46,89,213,140,62,84,135,228,99,196,252,93,147,201,203,82,65,33,255,178,106,37,18,6,45,133,14,234,113,38,232,214,98,75,164,25,134,54,218,174,197,98,251,250,33,85,246,46,128,208,32,233,40,6,36,214,209,15,54,209,53,15,113,107,39,253,193,66,139,143,27,27,125,174,61,112,189,201,85,76,38,133,36,163,101,53,34,167,175,26,77,247,11,131,3,153,67,91,11,68,207,98,174,13,31,34,134,216,2,25,153,22,58,17,131,84,36,252,38,61,110,113,198,89,181,115,119,232,182,137,223,1,13,227,97,201,207,175,26,230,219,81,212,139,28,63,134,157,249,171,12,192,131,96,212,116,144,233,246,137,61,140,1,246,191,152,106,187,135,110,54,102,180,206,21,186,140,149,249,27,255,111,128,14,69,83,251,25,229,143,251,83,63,235,221,68,144,252,109,46,38,122,73,25,226,175,207,41,84,86,248,11,244,3,71,242,99,22,247,98,252,128,2,209,252,189,209,136,240,66,40,169,188,91,36,126,49,62,186,39,76,25,152,189,205,253,126,101,92,109,196,138,170,107,21,248,0,2,19,24,196,65,217,159,136,150,196,189,124,81,97,115,178,194,155,86,106,248,130,72,246,131,61,122,180,183,214,243,216,53,236,81,250,192,148,13,147,155,115,190,166,240,149,49,231,242,89,180,141,8,190,149,52,56,117,41,164,231,17,239,94,235,31,229,54,34,13,92,121,11,238,80,173,29,12,121,3,136,169,97,53,1,134,96,185,65,76,117,4,48,129,179,187,133,228,229,50,15,173,95,218,81,252,35,80,187,41,135,69,9,46,86,121,109,61,101,6,165,7,192,109,191,148,17,147,104,100,38,149,26,120,147,120,236,90,184,158,144,85,211,166,242,0,65,78,225,63,8,190,101,126,160,59,167,138,46,153,18,85,145,62,102,103,209,234,233,255,206,232,232,150,21,66,195,229,233,43,146,48,80,237,107,93,137,68,249,83 };
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
