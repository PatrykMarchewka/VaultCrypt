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
        private readonly VaultCrypt.Services.VaultService _service;
        private readonly VaultCrypt.Services.FileService _fileService = new VaultCrypt.Services.FileService();
        private IVaultSession _session = TestsHelper.EmptySession;
        private readonly VaultCrypt.Services.EncryptionOptionsService _encryptionOptionsService = new VaultCrypt.Services.EncryptionOptionsService();
        private readonly VaultCrypt.Services.SystemService _systemService = new VaultCrypt.Services.SystemService();

        public VaultServiceTests()
        {
            _service = new VaultCrypt.Services.VaultService(_fileService, _encryptionOptionsService, _systemService);
        }

        private void ReplaceSession(IVaultSession newSession)
        {
            var copy = TestsHelper.CreateFilledSessionInstance(newSession.VERSION, newSession.KEY.AsSpan, newSession.VAULTPATH, new Dictionary<long, EncryptedFileInfo>(newSession.ENCRYPTED_FILES));

            _session = copy;
            VaultSession.CurrentSession = copy;
        }

        [Fact]
        internal void CreateVaultCreatesVaultFile()
        {
            var path = NormalizedPath.From(Path.GetTempPath());
            var fileName = Path.GetRandomFileName();
            byte[] password = new byte[1];
            int iterations = 10;
            IVaultReader vaultReader = TestsHelper.GetNewestReader;

            _service.CreateVault(path, fileName, password, iterations);
            try
            {
                //Asserting that new vault file has correct header
                using (FileStream fs = new FileStream($"{path}\\{fileName}.vlt", FileMode.Open, FileAccess.Read))
                {
                    Assert.Equal(vaultReader.HeaderSize, fs.Length);
                    Assert.Equal(VaultSession.NewestVaultVersion, fs.ReadByte());
                    ISecureBuffer salt = vaultReader.ReadSalt(fs);
                    Assert.False(salt.AsSpan.IndexOfAnyExcept((byte)0) == -1); //Asserting that salt is not empty (zeroed out value)
                    Assert.Equal(iterations, vaultReader.ReadIterationsNumber(fs));
                    long encryptedMetadataOffset = fs.Position;
                    byte[] encrypted = new byte[vaultReader.HeaderSize - encryptedMetadataOffset];
                    fs.Read(encrypted);
                    using (var decrypted = vaultReader.ReadAndDecryptData(fs, encryptedMetadataOffset, encrypted.Length))
                    {
                        Assert.Equal(sizeof(ushort) + vaultReader.MetadataOffsetsSize, decrypted.AsSpan.Length);
                        Assert.True(decrypted.AsSpan.IndexOfAnyExcept((byte)0) == -1);
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

                Assert.Equal(vaultInformation.Version, VaultSession.CurrentSession.VERSION);
                Assert.True(vaultInformation.VaultSession.KEY.AsSpan.SequenceEqual(VaultSession.CurrentSession.KEY.AsSpan));
                Assert.Equal(vaultPath, VaultSession.CurrentSession.VAULTPATH);
                Assert.True(CompareEncryptedFilesKVP(vaultInformation.VaultSession.ENCRYPTED_FILES, VaultSession.CurrentSession.ENCRYPTED_FILES));
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
                Assert.Equal(vaultInformation.VaultSession.ENCRYPTED_FILES.Count, _session.ENCRYPTED_FILES.Count);
                foreach (var item in vaultInformation.VaultSession.ENCRYPTED_FILES)
                {
                    long key = item.Key;
                    EncryptedFileInfo expected = item.Value;
                    EncryptedFileInfo actual = _session.ENCRYPTED_FILES[key];

                    Assert.Equal(expected.FileName, actual.FileName);
                    Assert.Equal(expected.EncryptionAlgorithm, actual.EncryptionAlgorithm);
                    Assert.Equal(expected.FileSize, actual.FileSize);
                }
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


        [Theory]
        [MemberData(nameof(TestsHelper.FilledVaultFileCombinations), MemberType = typeof(TestsHelper))]
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
        [MemberData(nameof(TestsHelper.FilledVaultFileCombinations), MemberType = typeof(TestsHelper))]
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
        [MemberData(nameof(TestsHelper.FilledVaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task DeleteFileFromVaultZeroesOutFile(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            IVaultReader vaultReader = VaultRegistry.GetVaultReader(vaultInformation.Version);

            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                var offsetToDelete = vaultInformation.VaultSession.ENCRYPTED_FILES.First().Key;
                await _service.DeleteFileFromVault(offsetToDelete, new ProgressionContext());
                byte[] actual = new byte[vaultReader.EncryptionOptionsSize];
                using (FileStream fs = new FileStream(vaultPath, FileMode.Open, FileAccess.Read))
                {
                    fs.Position = offsetToDelete;
                    fs.Read(actual);
                }
                Assert.True(actual.AsSpan().IndexOfAnyExcept((byte)0) == -1);
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.FilledVaultFileCombinations), MemberType = typeof(TestsHelper))]
        internal async Task DeleteFileFromVaultTrimsVault(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            ReplaceSession(vaultInformation.VaultSession);
            try
            {
                var info = new FileInfo(vaultPath);
                long oldVaultSize = info.Length;

                await _service.DeleteFileFromVault(_session.ENCRYPTED_FILES.Last().Key, new ProgressionContext());
                long newVaultSize = long.MaxValue;
                bool spinResult = SpinWait.SpinUntil(() =>
                {
                    //Trying to see if the file stream is closed from previous awaited method, returns true only if the file doesnt have any filestream open with it
                    //_service.DeleteFileFromVault uses retryhelper which runs Action using Task.Run to not block the UI, Task.Run returns before work is finished which creates a race condition in this test
                    info.Refresh();
                    newVaultSize = info.Length;
                    return oldVaultSize != newVaultSize;
                }, TimeSpan.FromSeconds(10)
                );
                Assert.True(spinResult);
                Assert.True(newVaultSize < oldVaultSize,$"{oldVaultSize} >= {newVaultSize}");
            }
            finally
            {
                File.Delete(vaultPath);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.FilledVaultFileCombinations), MemberType = typeof(TestsHelper))]
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
        internal void DeleteFileThrowsForInvalidOffset(Func<NormalizedPath> vaultMethod, TestsHelper.VaultInformation vaultInformation)
        {
            var vaultPath = vaultMethod();
            try
            {
                IVaultReader vaultReader = VaultRegistry.GetVaultReader(vaultInformation.Version);
                ReplaceSession(vaultInformation.VaultSession);
                Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _service.DeleteFileFromVault(vaultReader.HeaderSize - 1, new ProgressionContext()));
            }
            finally
            {
                File.Delete(vaultPath);
            }
            
        }

        [Fact]
        internal void DeleteFileThrowsForInvalidContext()
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.DeleteFileFromVault(long.MaxValue, null!));
        }
    }
}
