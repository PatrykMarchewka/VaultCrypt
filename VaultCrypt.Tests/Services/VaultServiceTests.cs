using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests.Services
{
    public class VaultServiceTests
    {
        private readonly VaultCrypt.Services.VaultService _service;
        private readonly VaultCrypt.Services.FileService _fileService;
        private readonly VaultSession _session;
        private readonly VaultCrypt.Services.EncryptionOptionsService _encryptionOptionsService;
        private readonly VaultCrypt.Services.SystemService _systemService;

        public VaultServiceTests()
        {
            _fileService = new VaultCrypt.Services.FileService();
            _session = TestsHelper.CreateFilledSessionInstanceWithReader();
            _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService(_session);
            _systemService = new VaultCrypt.Services.SystemService(_session);
            _service = new VaultCrypt.Services.VaultService(_fileService, _session, _encryptionOptionsService, _systemService, TestsHelper.CreateVaultRegistry(_session));
        }

        [Fact]
        void CreateVaultCreatesVaultFile()
        {
            var path = NormalizedPath.From(Path.GetTempPath());
            var fileName = Path.GetRandomFileName();
            byte[] password = RandomNumberGenerator.GetBytes(32);
            int iterations = 10;

            _service.CreateVault(path, fileName, password, iterations);
            try
            {
                using (FileStream fs = new FileStream($"{path}\\{fileName}.vlt", FileMode.Open, FileAccess.Read))
                {
                    Assert.Equal(_session.VAULT_READER.HeaderSize, fs.Length);
                    Assert.Equal(VaultSession.NewestVaultVersion, fs.ReadByte());
                    Assert.False(_session.VAULT_READER.ReadSalt(fs).AsSpan.SequenceEqual(new byte[_session.VAULT_READER.SaltSize])); //Asserting that salt is not empty (zeroed out value)
                    Assert.Equal(iterations, _session.VAULT_READER.ReadIterationsNumber(fs));
                }
            }
            finally
            {
                File.Delete($"{path}\\{fileName}.vlt");
            }
        }

        [Fact]
        void CreateVaultCreatesVaultFileInNewDirectory()
        {
            var path = NormalizedPath.From(Path.GetTempPath() + $"\\{RandomNumberGenerator.GetHexString(10)}");
            var fileName = Path.GetRandomFileName();
            byte[] password = RandomNumberGenerator.GetBytes(32);
            int iterations = 10;

            _service.CreateVault(path, fileName, password, iterations);
            try
            {
                Assert.True(File.Exists($"{path}\\{fileName}.vlt"));
            }
            finally
            {
                Directory.Delete(path!, recursive: true);
            }
        }

        [Fact]
        void CreateVaultThrowsForNullValues()
        {
            string nonNullValue = "TEXT";
            Assert.Throws<ArgumentNullException>(() => _service.CreateVault(null!, nonNullValue, new byte[1], 1));
            Assert.Throws<ArgumentNullException>(() => _service.CreateVault(NormalizedPath.From(nonNullValue), null!, new byte[1], 1));
        }

        [Fact]
        void CreateVaultThrowsForInvalidValues()
        {
            string nonNullValue = "TEXT";
            
            Assert.Throws<ArgumentException>(() => _service.CreateVault(NormalizedPath.From(string.Empty), nonNullValue, new byte[1], 1));
            Assert.Throws<ArgumentException>(() => _service.CreateVault(NormalizedPath.From("   "), nonNullValue, new byte[1], 1));

            Assert.Throws<ArgumentException>(() => _service.CreateVault(NormalizedPath.From(nonNullValue), string.Empty, new byte[1], 1));
            Assert.Throws<ArgumentException>(() => _service.CreateVault(NormalizedPath.From(nonNullValue), "    ", new byte[1], 1));

            Assert.Throws<ArgumentException>(() => _service.CreateVault(NormalizedPath.From(nonNullValue), nonNullValue, new byte[0], 1));
        }

        [Fact]
        void CreateVaultThrowsForNegativeValues()
        {
            string nonNullValue = "TEXT";
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CreateVault(NormalizedPath.From(nonNullValue), nonNullValue, new byte[1], -1));
        }

        [Fact]
        void CreateVaultThrowsForZeroValues()
        {
            string nonNullValue = "TEXT";
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CreateVault(NormalizedPath.From(nonNullValue), nonNullValue, new byte[1], 0));
        }

        [Fact]
        void CreateSessionFromFileSetsValuesCorrectly()
        {

            NormalizedPath vaultFile = null!;
            try
            {
                vaultFile = TestsHelper.CreateVaultFile();
                _service.CreateSessionFromFile(new byte[16], vaultFile);


                Assert.True(TestsHelper.CreateKey(new byte[16], new byte[32], 1000).SequenceEqual(_session.KEY.AsSpan[..PasswordHelper.KeySize]));
                Assert.Equal(vaultFile, _session.VAULTPATH);
                Assert.Empty(_session.ENCRYPTED_FILES);
                Assert.True(_session.VAULT_READER is VaultV0Reader);
            }
            finally
            {
                if (vaultFile is not null) File.Delete(vaultFile!);
            }
        }

        [Fact]
        void CreateSessionFromFileThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.CreateSessionFromFile(new byte[1], null!));
        }

        [Fact]
        void CreateSessionFromFileThrowsForInvalidValues()
        {
            Assert.Throws<ArgumentException>(() => _service.CreateSessionFromFile(new byte[0], NormalizedPath.From("VALID")));
            Assert.Throws<ArgumentException>(() => _service.CreateSessionFromFile(new byte[1], NormalizedPath.From("")));
            Assert.Throws<ArgumentException>(() => _service.CreateSessionFromFile(new byte[1], NormalizedPath.From("    ")));
        }

        [Fact]
        void RefreshEncryptedFilesListPopulatesFileListAndRefreshses()
        {
            _session.ENCRYPTED_FILES.Clear();
            byte expectedFileListCount = (byte)RandomNumberGenerator.GetInt32(10);

            (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) vaultInformation = (null!, null!);
            try
            {
                vaultInformation = TestsHelper.CreateVaultFileWithEncryptedFileList(expectedFileListCount, _session);

                using (FileStream fs = new FileStream(vaultInformation.Item1!, FileMode.Open, FileAccess.Read))
                {
                    _service.RefreshEncryptedFilesList(fs);
                }
                var fileList = _session.ENCRYPTED_FILES.ToList();
                Assert.Equal(expectedFileListCount, _session.ENCRYPTED_FILES.Count);
                for (int i = 0; i < expectedFileListCount; i++)
                {
                    Assert.Equal(Encoding.UTF8.GetString(vaultInformation.Item2[i].FileName.AsSpan), fileList[i].Value.FileName);
                    Assert.Equal(EncryptionAlgorithm.GetEncryptionAlgorithmInfo[vaultInformation.Item2[i].EncryptionAlgorithm].Name, fileList[i].Value.EncryptionAlgorithm);
                }
            }
            finally
            {
                if (vaultInformation.Item1 is not null) File.Delete(vaultInformation.Item1!);
                foreach (var item in vaultInformation.Item2)
                {
                    item.Dispose();
                }
            }
        }

        [Fact]
        void RefreshEncryptedFilesListThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.RefreshEncryptedFilesList(null!));
        }

        [Fact]
        void TrimVaultTrimsVaultAndSavesItToAFile()
        {
            byte[] password = Encoding.UTF8.GetBytes("TrimVaultTrims");

            (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) vaultInformation = (null!, null!);
            NormalizedPath newVaultPath = null!;
            try
            {
                vaultInformation = TestsHelper.CreateVaultFileWithEncryptedFileList(numberOfFiles: 10, _session, password);
                
                long oldVaultSize = new FileInfo(vaultInformation.Item1!).Length;
                //Trim vault uses vault provided at VaultSession.VAULTPATH where VaultSession is the one provided when creating service
                using (FileStream fs = new FileStream(vaultInformation.Item1.Value, FileMode.Open, FileAccess.Read))
                {
                    TestsHelper.SetVaultSessionFromStream(_session, fs, password);
                }
                _session.ENCRYPTED_FILES.Remove(_session.ENCRYPTED_FILES.First().Key);

                try
                {

                    _service.TrimVault(new ProgressionContext());
                    newVaultPath = NormalizedPath.From(vaultInformation.Item1!.Value[..^4] + "_TRIMMED.vlt");
                    long newVaultSize = new FileInfo(newVaultPath!).Length;
                    Assert.True(newVaultSize < oldVaultSize);
                }
                finally
                {
                    if (newVaultPath is not null) File.Delete(newVaultPath!);
                }
            }
            finally
            {
                if (vaultInformation.Item1 is not null) File.Delete(vaultInformation.Item1!);
                
            }
            
        }

        [Fact]
        void TrimVaultReturnsSameVaultIfThereIsNothingToTrim()
        {
            byte[] password = Encoding.UTF8.GetBytes("TrimVaultReturnsSameVaultIfThereIsNothingToTrim");


            (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) vaultInformation = (null!, null!);
            NormalizedPath newVaultPath = null!;
            try
            {
                vaultInformation = TestsHelper.CreateVaultFileWithEncryptedFileList(10, _session, password);
                //Trim vault uses vault provided at VaultSession.VAULTPATH where VaultSession is the one provided when creating service
                using (FileStream fs = new FileStream(vaultInformation.Item1.Value, FileMode.Open, FileAccess.Read))
                {
                    TestsHelper.SetVaultSessionFromStream(_session, fs, password);
                }
                try
                {
                    _service.TrimVault(new ProgressionContext());
                    newVaultPath = NormalizedPath.From(vaultInformation.Item1!.Value[..^4] + "_TRIMMED.vlt");
                    Assert.Equal(new FileInfo(vaultInformation.Item1!).Length, new FileInfo(newVaultPath!).Length);
                }
                finally
                {
                    File.Delete(newVaultPath!);
                }
            }
            finally
            {
                if (vaultInformation.Item1 is not null) File.Delete(vaultInformation.Item1!);
            }
        }

        [Fact]
        void TrimVaultThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.TrimVault(null!));
        }

        [Fact]
        void DeleteFileFromVaultZeroesOutFile()
        {
            (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) tuple = TestsHelper.CreateVaultFileWithEncryptedFileList(10, _session);
            var offset = _session.ENCRYPTED_FILES.First().Key;
            _service.DeleteFileFromVault(_session.ENCRYPTED_FILES.First().Key, new ProgressionContext());

            byte[] actual = new byte[_session.VAULT_READER.EncryptionOptionsSize];
            using (FileStream fs = new FileStream(tuple.Item1.Value, FileMode.Open, FileAccess.Read))
            {
                fs.Position = offset;
                fs.Read(actual);
            }

            Assert.True(new byte[_session.VAULT_READER.EncryptionOptionsSize].SequenceEqual(actual));

            File.Delete(tuple.Item1!);
        }

        [Fact]
        void DeleteFileFromVaultTrimsVault()
        {
            (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) tuple = TestsHelper.CreateVaultFileWithEncryptedFileList(10, _session);
            long oldVaultSize = new FileInfo(tuple.Item1!).Length;

            _service.DeleteFileFromVault(_session.ENCRYPTED_FILES.Last().Key, new ProgressionContext());

            long newVaultSize = new FileInfo(tuple.Item1!).Length;

            Assert.True(newVaultSize < oldVaultSize);

            File.Delete(tuple.Item1!);
        }

        [Fact]
        void DeleteFileFromVaultChangesEncryptedFileListCount()
        {
            (NormalizedPath, EncryptionOptions.FileEncryptionOptions[]) tuple = TestsHelper.CreateVaultFileWithEncryptedFileList(10, _session);
            long oldVaultSize = new FileInfo(tuple.Item1!).Length;

            var oldFileListCount = _session.ENCRYPTED_FILES.Count;
            _service.DeleteFileFromVault(_session.ENCRYPTED_FILES.Last().Key, new ProgressionContext());
            using (FileStream vaultFS = new FileStream(_session.VAULTPATH!, FileMode.Open, FileAccess.Read))
            {
                _service.RefreshEncryptedFilesList(vaultFS);
            }
            var actualFileListCount = _session.ENCRYPTED_FILES.Count;

            Assert.Equal(oldFileListCount - 1, actualFileListCount);
            File.Delete(tuple.Item1!);
        }

        [Fact]
        void DeleteFileThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.DeleteFileFromVault(1, null!));
        }

        [Fact]
        void DeleteFileThrowsForNegativeValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.DeleteFileFromVault(-1, new ProgressionContext()));
        }
    }
}
