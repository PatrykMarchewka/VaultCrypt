using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests.Services
{
    public class DecryptionServiceTests
    {
        private readonly VaultCrypt.Services.DecryptionService _service;
        private readonly VaultCrypt.Services.FileService _fileService;
        private readonly VaultCrypt.Services.EncryptionOptionsService _encryptionOptionsService;
        private readonly VaultSession _session;
        private readonly VaultCrypt.Services.SystemService _systemService;

        public DecryptionServiceTests()
        {
            _fileService = new VaultCrypt.Services.FileService();
            _session = TestsHelper.CreateFilledSessionInstanceWithReader();
            _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService(_session);
            _systemService = new VaultCrypt.Services.SystemService(_session);
            _service = new VaultCrypt.Services.DecryptionService(_fileService, _encryptionOptionsService, _session, _systemService);
        }



        [Fact]
        async Task DecryptCorrectlyDecryptsData()
        {
            byte[][] expectedFiles = new byte[10][];
            NormalizedPath[] filePaths = new NormalizedPath[10];
            for (int i = 0; i < expectedFiles.Length; i++)
            {
                expectedFiles[i] = RandomNumberGenerator.GetBytes(1000);
            }

            (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) vault = TestsHelper.CreateVaultFileWithEncryptedFileList(expectedFiles, _session);

            for (int i = 0; i < expectedFiles.Length; i++)
            {
                using (FileStream vaultFS = new FileStream(vault.Item1, FileMode.Open, FileAccess.Read))
                {
                    long offset = TestsHelper.GetOffsetKVPFromVaultAtPosition(i, vaultFS, _session).Key;
                    filePaths[i] = TestsHelper.CreateTemporaryFile(0);
                    await _service.Decrypt(offset, filePaths[i], new ProgressionContext());
                }
            }

            for (int i = 0; i < expectedFiles.Length; i++)
            {
                byte[] actual = File.ReadAllBytes(filePaths[i]!);
                Assert.True(expectedFiles[i].SequenceEqual(actual));
                File.Delete(filePaths[i]!);
            }
            File.Delete(vault.Item1);
        }

        [Fact]
        void DecryptThrowsForNullValues()
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () => await _service.Decrypt(long.MaxValue, null!, new ProgressionContext()));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await _service.Decrypt(long.MaxValue, NormalizedPath.From("VALID"), null!));
        }

        [Fact]
        void DecryptThrowsForInvalidValues()
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await _service.Decrypt(0, NormalizedPath.From("VALID"), new ProgressionContext()));
            Assert.ThrowsAsync<ArgumentException>(async () => await _service.Decrypt(long.MaxValue, NormalizedPath.From(""), new ProgressionContext()));
            Assert.ThrowsAsync<ArgumentException>(async () => await _service.Decrypt(long.MaxValue, NormalizedPath.From("   "), new ProgressionContext()));
        }
    }
}
