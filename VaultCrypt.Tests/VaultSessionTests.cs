using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt.Tests
{
    public class VaultSessionTests
    {
        private readonly VaultSession _session;

        public VaultSessionTests()
        {
            _session = TestsHelper.CreateEmptySessionInstance();
        }

        private void SetKey(byte[] key)
        {
            //Reflection to set the key value despite being private
            typeof(VaultSession).GetProperty(nameof(VaultSession.KEY))!.SetValue(_session, key);
        }

        [Fact]
        void CreateSessionSetsValuesCorrectly()
        {
            NormalizedPath vaultPath = NormalizedPath.From("CreateSessionTest");
            IVaultReader reader = new FakeVaultReader();
            ReadOnlySpan<byte> password = new byte[] { 1, 2, 3 };
            ReadOnlySpan<byte> salt = new byte[] { 4, 5, 6 };
            int iterations = 1;
            //Precomputed key value
            byte[] precomputedKey = new byte[128] { 242, 189, 23, 238, 9, 148, 95, 145, 100, 59, 125, 206, 125, 65, 65, 0, 156, 7, 34, 24, 21, 49, 137, 109, 160, 87, 70, 172, 10, 202, 219, 55, 178, 197, 107, 46, 239, 1, 106, 48, 117, 172, 239, 177, 123, 189, 31, 222, 223, 174, 20, 134, 122, 191, 3, 144, 70, 75, 175, 143, 201, 203, 61, 65, 239, 112, 7, 116, 8, 174, 83, 136, 218, 39, 119, 42, 166, 246, 94, 32, 193, 242, 30, 220, 162, 90, 53, 105, 94, 51, 88, 118, 219, 159, 96, 163, 93, 6, 231, 141, 136, 207, 253, 224, 56, 150, 12, 108, 10, 194, 143, 217, 113, 170, 61, 92, 56, 0, 5, 187, 205, 136, 50, 196, 171, 78, 20, 149 };

            _session.CreateSession(vaultPath, reader, password, salt, iterations);

            Assert.Equal(vaultPath, _session.VAULTPATH);
            Assert.Equal(reader, _session.VAULT_READER);
            Assert.Equal(precomputedKey, _session.KEY);
            Assert.Empty(_session.ENCRYPTED_FILES);
        }

        [Fact]
        void DisposeClearsValues()
        {
            _session.Dispose();

            Assert.Equal(Array.Empty<byte>(), _session.KEY);
            Assert.Empty(_session.ENCRYPTED_FILES);
            Assert.True(string.IsNullOrEmpty(_session.VAULTPATH) && _session.VAULTPATH is not null);
            Assert.Null(_session.VAULT_READER);
        }

        [Fact]
        void RaiseEncryptedFileListUpdatedRaisesEvent()
        {
            int eventRaisedCount = 0;
            _session.EncryptedFilesListUpdated += () => eventRaisedCount++;
            _session.RasiseEncryptedFileListUpdated();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        void GetSlicedKeyThrowsForTooBigSlice()
        {
            SetKey(new byte[] { 0, 1, 2 });
            Assert.Throws<ArgumentOutOfRangeException>(() => _session.GetSlicedKey(byte.MaxValue));
        }

        [Fact]
        void GetSlicedKeyReturnsCorrectlySlicedKey()
        {
            SetKey(new byte[] { 0, 1, 2 });
            var sliced = _session.GetSlicedKey(3).Span;

            for (int i = 0; i < 3; i++)
            {
                Assert.Equal(_session.KEY[i], sliced[i]);
            }
        }
    }

    public class VaultRegistryTests
    {
        private readonly VaultRegistry _registry;
        public VaultRegistryTests()
        {
            _registry = TestsHelper.CreateVaultRegistry(null!, null!);
        }

        [Fact]
        void GetVaultReaderReturnsCorrectValue()
        {
            var reader = _registry.GetVaultReader(0);
            Assert.Equal(0, reader.Version);
            Assert.True(reader is VaultV0Reader);
        }

        [Fact]
        void GetVaultReaderThrowsForNonExistentReader()
        {
            Assert.Throws<VaultException>(() => _registry.GetVaultReader(byte.MaxValue));
        }
    }
}
