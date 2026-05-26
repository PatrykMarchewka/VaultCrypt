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
        private VaultCrypt.Services.DecryptionService _service;
        private readonly VaultCrypt.Services.FileService _fileService = new VaultCrypt.Services.FileService();
        private VaultCrypt.Services.EncryptionOptionsService _encryptionOptionsService;
        private VaultSession _session = TestsHelper.EmptySession;
        private VaultCrypt.Services.SystemService _systemService;

        public DecryptionServiceTests()
        {
            _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService(_session);
            _systemService = new VaultCrypt.Services.SystemService(_session);
            _service = new VaultCrypt.Services.DecryptionService(_fileService, _encryptionOptionsService, _session, _systemService);
        }

        private void ReplaceSession(IVaultSession newSession)
        {
            _session = (VaultSession)newSession;
            _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService(_session);
            _systemService = new VaultCrypt.Services.SystemService(_session);
            _service = new VaultCrypt.Services.DecryptionService(_fileService, _encryptionOptionsService, _session, _systemService);
        }



        [Theory]
        [MemberData(nameof(TestsHelper.FilledVaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task DecryptCorrectlyDecryptsData(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vault = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            NormalizedPath decrypted = TestsHelper.CreateTemporaryFile(0);
            try
            {
                //First encrypted file should be LoremIpsum
                await _service.Decrypt(_session.ENCRYPTED_FILES.First().Key, decrypted, new ProgressionContext());
                byte[] expected = File.ReadAllBytes(TestsHelper.LoremIpsumFilePath);
                byte[] actual = File.ReadAllBytes(decrypted);
                Assert.True(expected.SequenceEqual(actual));
            }
            finally
            {
                File.Delete(vault);
                File.Delete(decrypted);
            }
        }

        [Theory]
        [InlineData(long.MinValue)]
        [InlineData(4096 - 1)] //V0 Metadata offsets size
        internal void DecryptThrowsForInvalidOffset(long metadataOffset)
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await _service.Decrypt(metadataOffset, NormalizedPath.From("VALID"), new ProgressionContext()));
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidPaths), MemberType = typeof(TestsHelper))]
        internal void DecryptThrowsForInvalidFilePath(NormalizedPath filePath, Type expectedException)
        {
            Assert.ThrowsAsync(expectedException, async () => await _service.Decrypt(long.MaxValue, filePath, new ProgressionContext()));
        }

        [Fact]
        internal void DecryptThrowsForInvalidContext()
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () => await _service.Decrypt(long.MaxValue, NormalizedPath.From("VALID"), null!));
        }
    }
}
