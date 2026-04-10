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
        private readonly FileService _fileService;
        private readonly VaultSession _vaultSession;
        private readonly EncryptionOptionsService _encryptionOptionsService;
        private readonly SystemService _systemService;
        private readonly EncryptionService _encryptionService;
        private readonly DecryptionService _decryptionService;
        private readonly VaultRegistry _registry;
        private readonly VaultService _vaultService;

        public WorkflowTests()
        {
            this._fileService = new FileService();
            this._vaultSession = TestsHelper.CreateEmptySessionInstance();
            this._encryptionOptionsService = new EncryptionOptionsService(_vaultSession);
            this._systemService = new SystemService(_vaultSession);
            this._encryptionService = new EncryptionService(_fileService, _encryptionOptionsService, _vaultSession, _systemService);
            this._decryptionService = new DecryptionService(_fileService, _encryptionOptionsService, _vaultSession, _systemService);
            this._registry = VaultRegistry.Initialize(_vaultSession);
            this._vaultService = new VaultService(_fileService, _vaultSession, _encryptionOptionsService, _systemService, _registry);
        }

        #region Helper methods and fields
        private byte[] PasswordBytes = new byte[] { 82, 0, 111, 0, 117, 0, 110, 0, 100, 0, 84, 0, 114, 0, 105, 0, 112, 0, 84, 0, 101, 0, 115, 0, 116, 0, 115, 0 }; //Translates to "RoundTripTests"
        private const int Iterations = 1_000_000;

        private string GetWorkflowDirectory
        {
            get
            {
                var appDirectory = AppContext.BaseDirectory;

                while (!Directory.Exists(Path.Combine(appDirectory, "Workflow")))
                {
                    appDirectory = Directory.GetParent(appDirectory)!.FullName;
                }

                return appDirectory;
            }
        }
        /// <summary>
        /// Empty vault with no files with it. V0 version created using release v1.3.0
        /// </summary>
        private NormalizedPath EmptyVaultV0FilePath => NormalizedPath.From($"{GetWorkflowDirectory}\\Workflow\\TestData\\EmptyVault_v0.vlt");

        /// <summary>
        /// Vault with lorem ipsum and pattern files in it. V0 version created using release v1.3.0
        /// </summary>
        private NormalizedPath FilledVaultV0FilePath => NormalizedPath.From($"{GetWorkflowDirectory}\\Workflow\\TestData\\FilledVault_v0.vlt");

        /// <summary>
        /// Lorem ipsum text file
        /// </summary>
        private NormalizedPath LoremIpsumFilePath => NormalizedPath.From($"{GetWorkflowDirectory}\\Workflow\\TestData\\LoremIpsum.txt");

        /// <summary>
        /// 17MB text file with repeating pattern data
        /// </summary>
        private NormalizedPath PatternFilePath => NormalizedPath.From($"{GetWorkflowDirectory}\\Workflow\\TestData\\PatternFile.txt");

        private string CreateRandomFileName(int nameLength = 10)
        {
            byte[] nameBytes = new byte[nameLength];
            for (int i = 0; i < nameLength; i++)
            {
                nameBytes[i] = (byte)RandomNumberGenerator.GetInt32(97, 123); //ASCII codes a-z
            }

            return Encoding.UTF8.GetString(nameBytes);
        }

        private NormalizedPath CreateEmptyVault(bool changeSession)
        {
            string directory = Path.GetTempPath();
            string random = CreateRandomFileName();
            var fullPath = NormalizedPath.From($"{directory}\\{random}.vlt");
            _vaultService.CreateVault(folderPath: NormalizedPath.From(directory), vaultName: random, password: PasswordBytes, Iterations);
            if (changeSession)
            {
                _vaultService.CreateSessionFromFile(PasswordBytes, fullPath);
            }
            return fullPath;
        }

        private NormalizedPath Copy(string fileName)
        {
            string directory = Path.GetTempPath();
            NormalizedPath fullNewPath = NormalizedPath.From($"{directory}\\{new FileInfo(fileName).Name}");
            File.Copy(fileName, fullNewPath);
            return fullNewPath;
        }

        private NormalizedPath CopyEmptyVaultV0(bool changeSession)
        {
            var copyPath = Copy(EmptyVaultV0FilePath);
            if (changeSession)
            {
                _vaultService.CreateSessionFromFile(PasswordBytes, copyPath);
            }

            return copyPath;
        }

        private NormalizedPath CopyFilledVaultV0(bool changeSession)
        {
            var copyPath = Copy(FilledVaultV0FilePath);
            if (changeSession)
            {
                _vaultService.CreateSessionFromFile(PasswordBytes, copyPath);
            }

            return copyPath;
        }

        private async Task<long> EncryptFile(NormalizedPath filePath)
        {
            await _encryptionService.Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo.AES256GCM, chunkSizeInMB: 1, filePath, new ProgressionContext());
            using (var vaultFS = new FileStream(_vaultSession.VAULTPATH, FileMode.Open, FileAccess.Read))
            {
                _vaultService.RefreshEncryptedFilesList(vaultFS);
            }
            return _vaultSession.ENCRYPTED_FILES.Last().Key; ;
        } 

        private async Task<NormalizedPath> DecryptFile(long offset)
        {
            NormalizedPath randomFileName = NormalizedPath.From($"{Path.GetTempPath()}\\{CreateRandomFileName()}");
            await _decryptionService.Decrypt(offset, randomFileName, new ProgressionContext());
            return randomFileName;
        }

        private NormalizedPath TrimVault(bool changeSession)
        {
            var trimmedVault = NormalizedPath.From(_vaultSession.VAULTPATH.Value[..^4] + "_TRIMMED.vlt");
            _vaultService.TrimVault(new ProgressionContext());
            if (changeSession)
            {
                _vaultService.CreateSessionFromFile(PasswordBytes, trimmedVault);
            }
            return trimmedVault;
        }
        #endregion


        async Task VaultEncryptsAndDecryptsCorrectlyNotChunked(NormalizedPath vaultPath)
        {
            try
            {
                long offset = await EncryptFile(LoremIpsumFilePath);
                NormalizedPath actualPattern = await DecryptFile(offset);
                try
                {
                    Assert.True(File.ReadAllBytes(LoremIpsumFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
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

        [Fact]
        async Task RunVaultEncryptsAndDecryptsCorrectlyNotChunked()
        {
            await VaultEncryptsAndDecryptsCorrectlyNotChunked(CreateEmptyVault(changeSession: true));
            await VaultEncryptsAndDecryptsCorrectlyNotChunked(CopyEmptyVaultV0(changeSession: true));
            await VaultEncryptsAndDecryptsCorrectlyNotChunked(CopyFilledVaultV0(changeSession: true));
        }

        

        async Task VaultEncryptsAndDecryptsCorrectlyChunked(NormalizedPath vaultPath)
        {
            try
            {
                long offset = await EncryptFile(PatternFilePath);
                NormalizedPath actualPattern = await DecryptFile(offset);
                try
                {
                    Assert.True(File.ReadAllBytes(PatternFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
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

        [Fact]
        async Task RunVaultEncryptsAndDecryptsCorrectlyChunked()
        {
            await VaultEncryptsAndDecryptsCorrectlyChunked(CreateEmptyVault(changeSession: true));
            await VaultEncryptsAndDecryptsCorrectlyChunked(CopyEmptyVaultV0(changeSession: true));
            await VaultEncryptsAndDecryptsCorrectlyChunked(CopyFilledVaultV0(changeSession: true));
        }

        async Task VaultEncryptsAndDecryptsCorrectlyMixed(NormalizedPath vaultPath)
        {
            try
            {
                long offsetLorem = await EncryptFile(LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(PatternFilePath);
                NormalizedPath actualLorem = await DecryptFile(offsetLorem);
                NormalizedPath actualPattern = await DecryptFile(offsetPattern);
                try
                {
                    Assert.True(File.ReadAllBytes(LoremIpsumFilePath).SequenceEqual(File.ReadAllBytes(actualLorem)));
                    Assert.True(File.ReadAllBytes(PatternFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
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

        [Fact]
        async Task RunVaultEncryptsAndDecryptsCorrectlyMixed()
        {
            await VaultEncryptsAndDecryptsCorrectlyMixed(CreateEmptyVault(changeSession: true));
            await VaultEncryptsAndDecryptsCorrectlyMixed(CopyEmptyVaultV0(changeSession: true));
            await VaultEncryptsAndDecryptsCorrectlyMixed(CopyFilledVaultV0(changeSession: true));
        }

        async Task VaultLowersFileSizeWhenDeletingLast(NormalizedPath vaultPath)
        {
            try
            {
                long offsetLorem = await EncryptFile(LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(PatternFilePath);
                _vaultService.DeleteFileFromVault(offsetPattern, new ProgressionContext());

                Assert.Equal(offsetPattern, new FileInfo(vaultPath).Length);
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Fact]
        async Task RunVaultLowersFileSizeWhenDeletingLast()
        {
            await VaultLowersFileSizeWhenDeletingLast(CreateEmptyVault(changeSession: true));
            await VaultLowersFileSizeWhenDeletingLast(CopyEmptyVaultV0(changeSession: true));
            await VaultLowersFileSizeWhenDeletingLast(CopyFilledVaultV0(changeSession: true));
        }

        async Task VaultZeroesDataWhenDeletingNotLast(NormalizedPath vaultPath)
        {
            try
            {
                long offsetLorem = await EncryptFile(LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(PatternFilePath);
                _vaultService.DeleteFileFromVault(offsetLorem, new ProgressionContext());
                byte[] actual = new byte[new FileInfo(LoremIpsumFilePath).Length];
                using (var vaultFs = new FileStream(vaultPath, FileMode.Open, FileAccess.Read))
                {
                    vaultFs.Position = offsetLorem;
                    vaultFs.Read(actual);
                }

                Assert.True(new byte[new FileInfo(LoremIpsumFilePath).Length].SequenceEqual(actual));
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Fact]
        async Task RunVaultZeroesDataWhenDeletingNotLast()
        {
            await VaultZeroesDataWhenDeletingNotLast(CreateEmptyVault(changeSession: true));
            await VaultZeroesDataWhenDeletingNotLast(CopyEmptyVaultV0(changeSession: true));
            await VaultZeroesDataWhenDeletingNotLast(CopyFilledVaultV0(changeSession: true));
        }

        async Task VaultTrimmedRemovesZeroedData(NormalizedPath vaultPath)
        {
            try
            {
                long offsetLorem = await EncryptFile(LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(PatternFilePath);

                _vaultService.DeleteFileFromVault(offsetLorem, new ProgressionContext());

                var trimmedVault = TrimVault(changeSession: true);
                try
                {
                    Assert.True(new FileInfo(trimmedVault).Length < new FileInfo(vaultPath).Length);
                    //Additional check to see if trimming didnt break existing file
                    var actualPattern = await DecryptFile(_vaultSession.ENCRYPTED_FILES.Last().Key);
                    try
                    {
                        Assert.True(File.ReadAllBytes(PatternFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
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

        [Fact]
        async Task RunVaultTrimmedRemovesZeroedData()
        {
            await VaultTrimmedRemovesZeroedData(CreateEmptyVault(changeSession: true));
            await VaultTrimmedRemovesZeroedData(CopyEmptyVaultV0(changeSession: true));
            await VaultTrimmedRemovesZeroedData(CopyFilledVaultV0(changeSession: true));
        }

        async Task VaultTrimmedEncryptsAndDecryptsCorrectly(NormalizedPath vaultPath)
        {
            try
            {
                long offsetLorem = await EncryptFile(LoremIpsumFilePath);
                long offsetPattern = await EncryptFile(PatternFilePath);

                _vaultService.DeleteFileFromVault(offsetPattern, new ProgressionContext());

                var trimmedVault = TrimVault(changeSession: true);
                try
                {
                    //Since deleted file is at the end, trimming does "nothing", It copies the existing header and files but generates new metadata with new IV
                    Assert.Equal(new FileInfo(trimmedVault).Length, new FileInfo(vaultPath).Length);
                    await EncryptFile(PatternFilePath);
                    NormalizedPath actualLorem = await DecryptFile(offsetLorem);
                    NormalizedPath actualPattern = await DecryptFile(offsetPattern);
                    try
                    {
                        Assert.True(File.ReadAllBytes(LoremIpsumFilePath).SequenceEqual(File.ReadAllBytes(actualLorem)));
                        Assert.True(File.ReadAllBytes(PatternFilePath).SequenceEqual(File.ReadAllBytes(actualPattern)));
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

        [Fact]
        async Task RunVaultTrimmedEncryptsAndDecryptsCorrectly()
        {
            await VaultTrimmedEncryptsAndDecryptsCorrectly(CreateEmptyVault(changeSession: true));
            await VaultTrimmedEncryptsAndDecryptsCorrectly(CopyEmptyVaultV0(changeSession: true));
            await VaultTrimmedEncryptsAndDecryptsCorrectly(CopyFilledVaultV0(changeSession: true));
        }
    }
}
