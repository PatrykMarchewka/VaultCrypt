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
        private readonly VaultCrypt.Services.FileService _fileService = new VaultCrypt.Services.FileService();
        private readonly VaultCrypt.Services.EncryptionOptionsService _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService();
        private readonly VaultCrypt.Services.SystemService _systemService = new VaultCrypt.Services.SystemService();

        public EncryptionServiceTests()
        {
            _service = new VaultCrypt.Services.EncryptionService(_fileService, _encryptionOptionsService, _systemService);
        }

        private void ReplaceSession(IVaultSession newSession)
        {
            var copy = TestsHelper.CreateFilledSessionInstance(newSession.VERSION, newSession.KEY.AsSpan, newSession.VAULTPATH, new Dictionary<long, EncryptedFileInfo>(newSession.ENCRYPTED_FILES));

            VaultSession.CurrentSession = copy;
        }

        

        [Theory]
        [MemberData(nameof(TestsHelper.EncryptionAlgorithmsAndVaultFileCombinationsCartesian), MemberType = typeof(TestsHelper))]
        internal async Task EncryptEncryptsDataToVaultChunked(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            IVaultReader vaultReader = VaultRegistry.GetVaultReader(vaultInformation.Version);

            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            var fileByteSize = (1024 * 1024 * 5) + 1; //5MB + 1 byte
            var expectedEncryptedByteSize = fileByteSize + vaultReader.EncryptionOptionsSize + (6 * algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize); //Original file + Encryption options + extra data per chunk (6 chunks, with last one being 1 byte, rest 1MB)
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
        [MemberData(nameof(TestsHelper.EncryptionAlgorithmsAndVaultFileCombinationsCartesian), MemberType = typeof(TestsHelper))]
        internal async Task EncryptEncryptsAndSavesToVaultNotChunked(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            IVaultReader vaultReader = VaultRegistry.GetVaultReader(vaultInformation.Version);

            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            var fileByteSize = (1024 * 1024) - 1; //1MB - 1 byte
            var expectedEncryptedByteSize = fileByteSize + vaultReader.EncryptionOptionsSize + algorithm.Provider().EncryptionAlgorithm.ExtraEncryptionDataSize;
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
        [MemberData(nameof(TestsHelper.InvalidPaths), MemberType = typeof(TestsHelper))]
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
