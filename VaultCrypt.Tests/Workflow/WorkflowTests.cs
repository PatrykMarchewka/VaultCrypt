using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt;
using VaultCrypt.Services;

namespace VaultCrypt.Tests.Workflow
{
    public class WorkflowTests
    {
        private readonly FileService _fileService = new FileService();
        private IVaultSession _vaultSession = TestsHelper.EmptySession;
        private readonly EncryptionOptionsService _encryptionOptionsService = new EncryptionOptionsService();
        private readonly SystemService _systemService = new SystemService();
        private readonly EncryptionService _encryptionService;
        private readonly DecryptionService _decryptionService;
        private readonly VaultService _vaultService;

        public WorkflowTests()
        {
            this._encryptionService = new EncryptionService(_fileService, _encryptionOptionsService, _systemService);
            this._decryptionService = new DecryptionService(_fileService, _encryptionOptionsService, _systemService);
            this._vaultService = new VaultService(_fileService, _encryptionOptionsService, _systemService);
        }

        #region Helper methods and fields

        private void ReplaceSession(IVaultSession newSession)
        {
            var copy = TestsHelper.CreateFilledSessionInstance(newSession.VERSION, newSession.KEY.AsSpan, newSession.VAULTPATH, new Dictionary<long, EncryptedFileInfo>(newSession.ENCRYPTED_FILES));

            _vaultSession = copy;
            VaultSession.CurrentSession = copy;
        }

        private void RefreshEncryptedFilesList()
        {
            using (var vaultFS = new FileStream(_vaultSession.VAULTPATH, FileMode.Open, FileAccess.Read))
            {
                _vaultService.RefreshEncryptedFilesList(vaultFS);
            }
        }

        private async Task<long> EncryptFile(NormalizedPath filePath)
        {
            await _encryptionService.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM, chunkSizeInMB: 1, filePath, new ProgressionContext());
            RefreshEncryptedFilesList();
            return _vaultSession.ENCRYPTED_FILES.Last().Key;
        } 

        private async Task<NormalizedPath> DecryptFile(long offset)
        {
            NormalizedPath randomFileName = NormalizedPath.From($"{Path.GetTempPath()}\\{TestsHelper.CreateRandomFileName()}");
            await _decryptionService.Decrypt(offset, randomFileName, new ProgressionContext());
            return randomFileName;
        }

        private async Task<NormalizedPath> TrimVault(bool changeSession)
        {
            var trimmedVault = NormalizedPath.From(_vaultSession.VAULTPATH.Value[..^4] + "_TRIMMED.vlt");
            await _vaultService.TrimVault(new ProgressionContext());
            if (changeSession)
            {
                _vaultService.CreateSessionFromFile(TestsHelper.TestDataVaultPassword, trimmedVault);
            }
            return trimmedVault;
        }
        #endregion

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task VaultEncryptsAndDecryptsCorrectlyNotChunked(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            NormalizedPath vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                await EncryptFile(TestsHelper.LoremIpsumFilePath);
                RefreshEncryptedFilesList();
                var offset = _vaultSession.ENCRYPTED_FILES.Last().Key;
                NormalizedPath actualPattern = await DecryptFile(offset);
                try
                {
                    Assert.True(File.ReadAllBytes(TestsHelper.LoremIpsumFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
                }
                finally
                {
                    File.Delete(actualPattern);
                }
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task VaultEncryptsAndDecryptsCorrectlyChunked(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            NormalizedPath vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                long offset = await EncryptFile(TestsHelper.PatternFilePath);
                NormalizedPath actualPattern = await DecryptFile(offset);
                try
                {
                    Assert.True(File.ReadAllBytes(TestsHelper.PatternFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
                }
                finally
                {
                    File.Delete(actualPattern);
                }
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task VaultEncryptsAndDecryptsCorrectlyMixed(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            NormalizedPath vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                long offsetLorem = await EncryptFile(TestsHelper.LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(TestsHelper.PatternFilePath);
                NormalizedPath actualLorem = await DecryptFile(offsetLorem);
                NormalizedPath actualPattern = await DecryptFile(offsetPattern);
                try
                {
                    Assert.True(File.ReadAllBytes(TestsHelper.LoremIpsumFilePath).SequenceEqual(File.ReadAllBytes(actualLorem)));
                    Assert.True(File.ReadAllBytes(TestsHelper.PatternFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
                }
                finally
                {
                    File.Delete(actualLorem);
                    File.Delete(actualPattern);
                }
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task VaultLowersFileSizeWhenDeletingLast(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            NormalizedPath vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                long offsetLorem = await EncryptFile(TestsHelper.LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(TestsHelper.PatternFilePath);
                await _vaultService.DeleteFileFromVault(offsetPattern, new ProgressionContext());

                Assert.Equal(offsetPattern, new FileInfo(vaultPath).Length);
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task VaultZeroesDataWhenDeletingNotLast(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            NormalizedPath vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                long offsetLorem = await EncryptFile(TestsHelper.LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(TestsHelper.PatternFilePath);
                await _vaultService.DeleteFileFromVault(offsetLorem, new ProgressionContext());
                byte[] actual = new byte[new FileInfo(TestsHelper.LoremIpsumFilePath).Length];
                using (var vaultFs = new FileStream(vaultPath, FileMode.Open, FileAccess.Read))
                {
                    vaultFs.Position = offsetLorem;
                    vaultFs.Read(actual);
                }
                Assert.True(actual.AsSpan().IndexOfAnyExcept((byte)0) == -1);
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task VaultTrimmedRemovesZeroedData(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            NormalizedPath vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                long offsetLorem = await EncryptFile(TestsHelper.LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(TestsHelper.PatternFilePath);

                await _vaultService.DeleteFileFromVault(offsetLorem, new ProgressionContext());

                //Refreshing file List to avoid trying to read stale data
                RefreshEncryptedFilesList();

                var trimmedVault = await TrimVault(changeSession: true);
                try
                {
                    Assert.True(new FileInfo(trimmedVault).Length < new FileInfo(vaultPath).Length);
                    //Additional check to see if trimming didnt break existing file
                    var actualPattern = await DecryptFile(_vaultSession.ENCRYPTED_FILES.Last().Key);
                    try
                    {
                        Assert.True(File.ReadAllBytes(TestsHelper.PatternFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
                    }
                    finally
                    {
                        File.Delete(actualPattern);
                    }
                }
                finally
                {
                    File.Delete(trimmedVault);
                }
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task VaultTrimmedEncryptsAndDecryptsCorrectly(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            NormalizedPath vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                long offsetLorem = await EncryptFile(TestsHelper.LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(TestsHelper.PatternFilePath);

                await _vaultService.DeleteFileFromVault(offsetPattern, new ProgressionContext());

                var trimmedVault = await TrimVault(changeSession: true);
                try
                {
                    //Since deleted file is at the end, trimming does "nothing", It copies the existing header and files but generates new metadata with new IV
                    Assert.Equal(new FileInfo(trimmedVault).Length, new FileInfo(vaultPath).Length);
                    await EncryptFile(TestsHelper.PatternFilePath);
                    NormalizedPath actualLorem = await DecryptFile(offsetLorem);
                    NormalizedPath actualPattern = await DecryptFile(offsetPattern);
                    try
                    {
                        Assert.True(File.ReadAllBytes(TestsHelper.LoremIpsumFilePath).SequenceEqual(File.ReadAllBytes(actualLorem)));
                        Assert.True(File.ReadAllBytes(TestsHelper.PatternFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
                    }
                    finally
                    {
                        File.Delete(actualLorem);
                        File.Delete(actualPattern);
                    }
                }
                finally
                {
                    File.Delete(trimmedVault);
                }
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }
    }
}
