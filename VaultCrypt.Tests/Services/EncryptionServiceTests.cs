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
        private VaultCrypt.Services.EncryptionService _service;
        private readonly VaultCrypt.Services.FileService _fileService = new VaultCrypt.Services.FileService();
        private VaultCrypt.Services.EncryptionOptionsService _encryptionOptionsService;
        private VaultSession _session = TestsHelper.EmptySession;
        private VaultCrypt.Services.SystemService _systemService;

        public EncryptionServiceTests()
        {
            _fileService = new VaultCrypt.Services.FileService();
            _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService(_session);
            _systemService = new VaultCrypt.Services.SystemService(_session);
            _service = new VaultCrypt.Services.EncryptionService(_fileService, _encryptionOptionsService, _session, _systemService);
        }

        private void ReplaceSession(IVaultSession newSession)
        {
            _session = (VaultSession)newSession;
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

        public static IEnumerable<object[]> EncryptionServiceTestCases()
        {
            foreach (var algorithmObject in EncryptionAlgorithms)
            {
                foreach (var vaultFile in TestsHelper.VaultFileCombinations)
                {
                    var algorithm = (EncryptionAlgorithm.EncryptionAlgorithmInfo)algorithmObject[0];
                    var method = (Func<NormalizedPath>)vaultFile[0];
                    var information = ((TestsHelper.VaultInformation)vaultFile[1]);

                    yield return new object[] { algorithm, method, information };
                }
            }
        }

        [Theory]
        [MemberData(nameof(EncryptionServiceTestCases))]
        internal async Task EncryptEncryptsDataToVaultChunked(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            var fileByteSize = (1024 * 1024 * 5) + 1; //5MB + 1 byte
            var expectedEncryptedByteSize = fileByteSize + vaultInformation.VaultSession.VAULT_READER.EncryptionOptionsSize + (6 * algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize); //Original file + Encryption options + extra data per chunk (6 chunks, with last one being 1 byte, rest 1MB)
            var fileToEncrypt = TestsHelper.CreateTemporaryFile(fileByteSize);
            try
            {
                FileInfo vaultInfo = new FileInfo(vaultPath);
                long vaultFileSize = vaultInfo.Length;
                await _service.Encrypt(algorithm, chunkSizeInMB: 1, fileToEncrypt, new ProgressionContext());

                vaultInfo.Refresh();
                long newVaultFileSize = vaultInfo.Length;
                Assert.Equal(vaultFileSize + expectedEncryptedByteSize, newVaultFileSize);
            }
            finally
            {
                File.Delete(vaultPath);
                File.Delete(fileToEncrypt);
            }
        }

        [Theory]
        [MemberData(nameof(EncryptionServiceTestCases))]
        internal async Task EncryptEncryptsAndSavesToVaultNotChunked(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            var fileByteSize = (1024 * 1024) - 1; //1MB - 1 byte
            var expectedEncryptedByteSize = fileByteSize + vaultInformation.VaultSession.VAULT_READER.EncryptionOptionsSize + algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize;
            var fileToEncrypt = TestsHelper.CreateTemporaryFile(fileByteSize);
            try
            {
                FileInfo vaultInfo = new FileInfo(vaultPath);
                long vaultFileSize = vaultInfo.Length;
                await _service.Encrypt(algorithm, chunkSizeInMB: 1, fileToEncrypt, new ProgressionContext());

                vaultInfo.Refresh();
                long newVaultFileSize = vaultInfo.Length;
                Assert.Equal(vaultFileSize + expectedEncryptedByteSize, newVaultFileSize);
            }
            finally
            {
                File.Delete(vaultPath);
                File.Delete(fileToEncrypt);
            }
        }


        [Fact]
        internal void EncryptThrowsForInvalidAlgorithm()
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () => await _service.Encrypt(null!, 1, NormalizedPath.From("VALID"), new ProgressionContext()));
        }

        [Theory]
        [InlineData(0)]
        internal void EncryptThrowsForInvalidChunkSize(ushort chunkSize)
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await _service.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM, chunkSize, NormalizedPath.From("VALID"), new ProgressionContext()));
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidPath), MemberType = typeof(TestsHelper))]
        internal void EncryptThrowsForInvalidFilePath(NormalizedPath filePath, Type expectedException)
        {
            Assert.ThrowsAsync(expectedException, async () => await _service.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM, 1, filePath, new ProgressionContext()));
        }

        [Fact]
        internal void EncryptThrowsForInvalidProgressionContext()
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () => await _service.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES128GCM, 1, NormalizedPath.From("VALID"), null!));
        }
    }
}
