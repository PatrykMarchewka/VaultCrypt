using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests.Services
{
    public class VaultServiceTests
    {
        private VaultCrypt.Services.VaultService _service;
        private readonly VaultCrypt.Services.FileService _fileService = new VaultCrypt.Services.FileService();
        private VaultSession _session;
        private VaultCrypt.Services.EncryptionOptionsService _encryptionOptionsService;
        private VaultCrypt.Services.SystemService _systemService;

        public VaultServiceTests()
        {
            _session = TestsHelper.EmptySession;
            _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService(_session);
            _systemService = new VaultCrypt.Services.SystemService(_session);
            _service = new VaultCrypt.Services.VaultService(_fileService, _session, _encryptionOptionsService, _systemService, TestsHelper.CreateVaultRegistry(_session));
        }

        private void ReplaceSession(IVaultSession newSession)
        {
            _session = (VaultSession)newSession;
            _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService(_session);
            _systemService = new VaultCrypt.Services.SystemService(_session);
            _service = new VaultCrypt.Services.VaultService(_fileService, _session, _encryptionOptionsService, _systemService, TestsHelper.CreateVaultRegistry(_session));
        }

        [Fact]
        internal void CreateVaultCreatesVaultFile()
        {
            var path = NormalizedPath.From(Path.GetTempPath());
            var fileName = Path.GetRandomFileName();
            byte[] password = new byte[1];
            int iterations = 10;

            _service.CreateVault(path, fileName, password, iterations);
            try
            {
                //Asserting that new vault file has correct header
                using (FileStream fs = new FileStream($"{path}\\{fileName}.vlt", FileMode.Open, FileAccess.Read))
                {
                    Assert.Equal(_session.VAULT_READER.HeaderSize, fs.Length);
                    Assert.Equal(VaultSession.NewestVaultVersion, fs.ReadByte());
                    Assert.False(_session.VAULT_READER.ReadSalt(fs).AsSpan.SequenceEqual(new byte[_session.VAULT_READER.SaltSize])); //Asserting that salt is not empty (zeroed out value)
                    Assert.Equal(iterations, _session.VAULT_READER.ReadIterationsNumber(fs));
                    long encryptedMetadataOffset = fs.Position;
                    byte[] encrypted = new byte[_session.VAULT_READER.HeaderSize - encryptedMetadataOffset];
                    fs.Read(encrypted);
                    using (var decrypted = _session.VAULT_READER.ReadAndDecryptData(fs, encryptedMetadataOffset, encrypted.Length))
                    {
                        Assert.True(decrypted.AsSpan.SequenceEqual(new byte[sizeof(ushort) + _session.VAULT_READER.MetadataOffsetsSize]));
                    }
                }
            }
            finally
            {
                File.Delete($"{path}\\{fileName}.vlt");
            }
        }

        [Fact]
        internal void CreateVaultCreatesVaultFileInNewDirectory()
        {
            var path = NormalizedPath.From(Path.GetTempPath() + $"\\{RandomNumberGenerator.GetHexString(10)}");
            var fileName = Path.GetRandomFileName();
            byte[] password = new byte[1];
            int iterations = 10;

            _service.CreateVault(path, fileName, password, iterations);
            try
            {
                Assert.True(File.Exists($"{path}\\{fileName}.vlt"));
            }
            finally
            {
                Directory.Delete(path, recursive: true);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidPaths), MemberType = typeof(TestsHelper))]
        internal void CreateVaultThrowsForInvalidFolderPath(NormalizedPath folderPath, Type expectedException)
        {
            Assert.Throws(expectedException, () => _service.CreateVault(folderPath, "TEXT", new byte[1], 1));
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidStrings), MemberType = typeof(TestsHelper))]
        internal void CreateVaultThrowsForInvalidVaultName(string vaultName, Type expectedException)
        {
            Assert.Throws(expectedException, () => _service.CreateVault(NormalizedPath.From("TEXT"), vaultName, new byte[1], 1));
        }

        [Fact]
        internal void CreateVaultThrowsForInvalidPassword()
        {
            Assert.Throws<ArgumentException>(() => _service.CreateVault(NormalizedPath.From("TEXT"), "TEXT", new byte[0], 1));
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        internal void CreateVaultThrowsForInvalidIterations(int iterations)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CreateVault(NormalizedPath.From("TEXT"), "TEXT", new byte[1], iterations));
        }

        private bool CompareEncryptedFilesKVP(Dictionary<long, EncryptedFileInfo> first, Dictionary<long, EncryptedFileInfo> second)
        {
            return first.Count == second.Count && 
                first.All(kvp => second.TryGetValue(kvp.Key, out EncryptedFileInfo info) && 
                kvp.Value.FileName == info.FileName && 
                kvp.Value.FileSize == info.FileSize &&
                kvp.Value.EncryptionAlgorithm == info.EncryptionAlgorithm);
        }

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal void CreateSessionFromFileSetsValuesCorrectly(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            try
            {
                _service.CreateSessionFromFile(vaultInformation.Password, vaultPath);

                Assert.True(vaultInformation.VaultSession.KEY.AsSpan.SequenceEqual(_session.KEY.AsSpan));
                Assert.Equal(vaultPath, _session.VAULTPATH);
                Assert.True(CompareEncryptedFilesKVP(vaultInformation.VaultSession.ENCRYPTED_FILES, _session.ENCRYPTED_FILES));
                Assert.Equal(vaultInformation.VaultSession.VAULT_READER.GetType(), _session.VAULT_READER.GetType());
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Fact]
        internal void CreateSessionFromFileThrowsOnInvalidPassword()
        {
            Assert.Throws<ArgumentException>(() => _service.CreateSessionFromFile(new byte[0], NormalizedPath.From("VALID")));
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidPaths), MemberType = typeof(TestsHelper))]
        internal void CreateSessionFromFileThrowsOnInvalidPath(NormalizedPath path, Type expectedException)
        {
            Assert.Throws(expectedException, () => _service.CreateSessionFromFile(new byte[1], path));
        }

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal void RefreshEncryptedFilesListPopulatesFileListAndRefreshses(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                using (FileStream fs = new FileStream(vaultPath, FileMode.Open, FileAccess.Read))
                {
                    _service.RefreshEncryptedFilesList(fs);
                }
                Assert.Equal(vaultInformation.VaultSession.ENCRYPTED_FILES, _session.ENCRYPTED_FILES);
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Fact]
        internal void RefreshEncryptedFilesListThrowsForInvalidStream()
        {
            Assert.Throws<ArgumentNullException>(() => _service.RefreshEncryptedFilesList(null!));
        }

        public static IEnumerable<object[]> FilledVaultFileCombinations => TestsHelper.VaultFileCombinations.Where(combination => ((TestsHelper.VaultInformation)combination[1]).VaultSession.ENCRYPTED_FILES.Count > 0);


        [Theory]
        [MemberData(nameof(FilledVaultFileCombinations))]
        internal async Task TrimVaultTrimsVaultAndSavesItToAFile(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            NormalizedPath newVaultPath = null!;
            try
            {
                long oldVaultSize = new FileInfo(vaultPath).Length;
                try
                {
                    _session.ENCRYPTED_FILES.Remove(_session.ENCRYPTED_FILES.First().Key);

                    await _service.TrimVault(new ProgressionContext());
                    newVaultPath = NormalizedPath.From(vaultPath.Value[..^4] + "_TRIMMED.vlt");
                    long newVaultSize = new FileInfo(newVaultPath).Length;
                    Assert.True(newVaultSize < oldVaultSize);
                }
                finally
                {
                    if (newVaultPath is not null) File.Delete(newVaultPath);
                }
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        

        [Theory]
        [MemberData(nameof(FilledVaultFileCombinations))]
        internal async Task TrimVaultReturnsSameVaultIfThereIsNothingToTrim(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            NormalizedPath newVaultPath = null!;
            try
            {
                await _service.TrimVault(new ProgressionContext());
                newVaultPath = NormalizedPath.From(vaultPath.Value[..^4] + "_TRIMMED.vlt");
                Assert.Equal(new FileInfo(vaultPath).Length, new FileInfo(newVaultPath).Length);
            }
            finally
            {
                File.Delete(vaultPath);
                if (newVaultPath is not null) File.Delete(newVaultPath);
            }
        }

        [Fact]
        internal void TrimVaultThrowsForInvalidContext()
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.TrimVault(null!));
        }

        [Theory]
        [MemberData(nameof(FilledVaultFileCombinations))]
        internal async Task DeleteFileFromVaultZeroesOutFile(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                var offsetToDelete = vaultInformation.VaultSession.ENCRYPTED_FILES.First().Key;
                await _service.DeleteFileFromVault(offsetToDelete, new ProgressionContext());
                byte[] actual = new byte[_session.VAULT_READER.EncryptionOptionsSize];
                using (FileStream fs = new FileStream(vaultPath, FileMode.Open, FileAccess.Read))
                {
                    fs.Position = offsetToDelete;
                    fs.Read(actual);
                }
                Assert.True(new byte[_session.VAULT_READER.EncryptionOptionsSize].SequenceEqual(actual));
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(FilledVaultFileCombinations))]
        internal async Task DeleteFileFromVaultTrimsVault(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                long oldVaultSize = new FileInfo(vaultPath).Length;

                await _service.DeleteFileFromVault(_session.ENCRYPTED_FILES.Last().Key, new ProgressionContext());

                long newVaultSize = new FileInfo(vaultPath).Length;

                Assert.True(newVaultSize < oldVaultSize);
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(FilledVaultFileCombinations))]
        internal async Task DeleteFileFromVaultChangesEncryptedFileListCount(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                long oldVaultSize = new FileInfo(vaultPath).Length;

                var oldFileListCount = _session.ENCRYPTED_FILES.Count;
                await _service.DeleteFileFromVault(_session.ENCRYPTED_FILES.Last().Key, new ProgressionContext());
                using (FileStream vaultFS = new FileStream(vaultPath, FileMode.Open, FileAccess.Read))
                {
                    _service.RefreshEncryptedFilesList(vaultFS);
                }
                var actualFileListCount = _session.ENCRYPTED_FILES.Count;

                Assert.Equal(oldFileListCount - 1, actualFileListCount);
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.VaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal void DeleteFileThrowsForInvalidOffset(Func<NormalizedPath> _, TestsHelper.VaultInformation vaultInformation)
        {
            ReplaceSession(vaultInformation.VaultSession);
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _service.DeleteFileFromVault(vaultInformation.VaultSession.VAULT_READER.HeaderSize - 1, new ProgressionContext()));
        }

        [Fact]
        internal void DeleteFileThrowsForInvalidContext()
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.DeleteFileFromVault(long.MaxValue, null!));
        }
    }
}
