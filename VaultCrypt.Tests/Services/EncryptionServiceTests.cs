using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests.Services
{
    public class EncryptionServiceTests
    {
        private readonly VaultCrypt.Services.EncryptionService _service;
        private readonly VaultCrypt.Services.FileService _fileService;
        private readonly VaultCrypt.Services.EncryptionOptionsService _encryptionOptionsService;
        private readonly VaultSession _session;
        private readonly VaultCrypt.Services.SystemService _systemService;

        public EncryptionServiceTests()
        {
            _fileService = new VaultCrypt.Services.FileService();
            _session = TestsHelper.CreateFilledSessionInstanceWithReader();
            _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService(_session);
            _systemService = new VaultCrypt.Services.SystemService(_session);
            _service = new VaultCrypt.Services.EncryptionService(_fileService, _encryptionOptionsService, _session, _systemService);
        }

        public static IEnumerable<object[]> EncryptionAlgorithms => new List<object[]>
        {
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES192GCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128CCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES192CCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256CCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.ChaCha20Poly1305},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128EAX},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES192EAX},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256EAX},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Twofish128CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Twofish192CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Twofish256CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Threefish256CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Threefish512CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Threefish1024CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent128GCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent192GCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent256GCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent128CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent192CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Serpent256CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia128GCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia192GCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia256GCM},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia128OCB},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia192OCB},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia256OCB},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia128CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia192CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.Camelia256CTR},
            new object[]{ EncryptionAlgorithm.EncryptionAlgorithmInfo.XSalsa20}
        };

        [Theory]
        [MemberData(nameof(EncryptionAlgorithms))]
        async Task EncryptEncryptsAndSavesToVaultChunked(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm)
        {
            var vaultPath = TestsHelper.CreateVaultFile();

            FileInfo vaultInfo = new FileInfo(vaultPath!);
            long vaultFileSize = vaultInfo.Length;
            using (FileStream vaultFS = new FileStream(vaultPath!, FileMode.Open, FileAccess.ReadWrite))
            {
                
                TestsHelper.SetVaultSessionFromStream(_session, vaultFS);
            }
            int oneMBBytes = (1024 * 1024);
            //Create a massive file to make sure that after encryption the chunks modify EncryptedFileInfo.FileSize value
            var fileToEncrypt = TestsHelper.CreateTemporaryFile(RandomNumberGenerator.GetInt32(oneMBBytes * 400 + 1, oneMBBytes * 500));

            await _service.Encrypt(algorithm, 1, fileToEncrypt, new ProgressionContext());

            vaultInfo.Refresh();
            long newVaultFileSize = vaultInfo.Length;
            FileInfo expectedFileInfo = new FileInfo(fileToEncrypt!);
            EncryptedFileInfo expectedEncryptedFileInfo = new EncryptedFileInfo(expectedFileInfo.Name, (ulong)(expectedFileInfo.Length + algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize), algorithm);
            EncryptedFileInfo actualEncryptedFileInfo = null!;
            using (FileStream vaultFS = new FileStream(vaultPath!, FileMode.Open, FileAccess.ReadWrite))
            {

                actualEncryptedFileInfo = TestsHelper.GetOffsetKVPFromVaultAtPosition(0, vaultFS, _session).Value;
            }

            Assert.Equal(expectedEncryptedFileInfo.FileName, actualEncryptedFileInfo.FileName);
            Assert.True(expectedEncryptedFileInfo.FileSize != actualEncryptedFileInfo.FileSize); //We cant predict how many chunks will be created, however with how many are created due to file they should generate atleast 1KB extra shifting the fileSize output
            Assert.Equal(expectedEncryptedFileInfo.EncryptionAlgorithm, actualEncryptedFileInfo.EncryptionAlgorithm);

            Assert.True((vaultFileSize + expectedFileInfo.Length + algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize + _session.VAULT_READER.EncryptionOptionsSize) < newVaultFileSize); //We cant predict how many chunks will be created so we just assert that the final file size is bigger than one chunk encrypt

            File.Delete(vaultPath!);
            File.Delete(fileToEncrypt!);
        }

        [Theory]
        [MemberData(nameof(EncryptionAlgorithms))]
        async Task EncryptEncryptsAndSavesToVaultNotChunked(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm)
        {
            var vaultPath = TestsHelper.CreateVaultFile();
            FileInfo vaultInfo = new FileInfo(vaultPath!);
            long vaultFileSize = vaultInfo.Length;
            using (FileStream vaultFS = new FileStream(vaultPath!, FileMode.Open, FileAccess.ReadWrite))
            {

                TestsHelper.SetVaultSessionFromStream(_session, vaultFS);
            }
            var fileToEncrypt = TestsHelper.CreateTemporaryFile(RandomNumberGenerator.GetInt32(1, (1024 * 1024) - 1));

            await _service.Encrypt(algorithm, 1, fileToEncrypt, new ProgressionContext());

            vaultInfo.Refresh();
            long newVaultFileSize = vaultInfo.Length;
            FileInfo expectedFileInfo = new FileInfo(fileToEncrypt!);
            EncryptedFileInfo expectedEncryptedFileInfo = new EncryptedFileInfo(expectedFileInfo.Name, (ulong)(expectedFileInfo.Length + algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize), algorithm);
            EncryptedFileInfo actualEncryptedFileInfo = null!;
            using (FileStream vaultFS = new FileStream(vaultPath!, FileMode.Open, FileAccess.ReadWrite))
            {

                actualEncryptedFileInfo = TestsHelper.GetOffsetKVPFromVaultAtPosition(0, vaultFS, _session).Value;
            }

            Assert.Equal(expectedEncryptedFileInfo.FileName, actualEncryptedFileInfo.FileName);
            Assert.Equal(expectedEncryptedFileInfo.FileSize, actualEncryptedFileInfo.FileSize);
            Assert.Equal(expectedEncryptedFileInfo.EncryptionAlgorithm, actualEncryptedFileInfo.EncryptionAlgorithm);

            Assert.Equal((vaultFileSize + expectedFileInfo.Length + algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize + _session.VAULT_READER.EncryptionOptionsSize), newVaultFileSize);

            File.Delete(vaultPath!);
            File.Delete(fileToEncrypt!);
        }

        [Fact]
        void EncryptThrowsForNullValues()
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () => await _service.Encrypt(null!, 1, NormalizedPath.From("VALID"), new ProgressionContext()));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await _service.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM, 1, null!, new ProgressionContext()));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await _service.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM, 1, NormalizedPath.From("VALID"), null!));
        }

        [Fact]
        void EncryptThrowsForZeroValues()
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await _service.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM, 0, NormalizedPath.From("VALID"), new ProgressionContext()));
        }

        [Fact]
        void EncryptThrowsForInvalidValues()
        {
            Assert.ThrowsAsync<ArgumentException>(async () => await _service.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM, 1, NormalizedPath.From("    "), new ProgressionContext()));
            Assert.ThrowsAsync<ArgumentException>(async () => await _service.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM, 1, NormalizedPath.From(string.Empty), new ProgressionContext()));
        }


    }
}
