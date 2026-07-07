using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests.Services
{
    public class SystemServiceTests
    {
        private readonly VaultCrypt.Services.SystemService _service;
        private readonly VaultSession _session = (VaultSession)TestsHelper.EmptyVaultV0Information.VaultSession; //Using existing vault information to ensure VAULTPATH is set correclty

        public SystemServiceTests()
        {
            _service = new VaultCrypt.Services.SystemService(_session);
        }

        [Fact]
        internal void CheckFreeSpaceDoesNotThrowForValidValues()
        {
            var path = TestsHelper.CreateTemporaryFile(0);
            try
            {
                _service.CheckFreeSpace(NormalizedPath.From(path));
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidPaths), MemberType = typeof(TestsHelper))]
        internal void CheckFreeSpaceThrowsForInvalidFilePath(NormalizedPath filePath, Type expectedException)
        {
            Assert.Throws(expectedException, () => _service.CheckFreeSpace(NormalizedPath.From(filePath)));
        }

        [Fact]
        internal void CalculateConcurrencyOneOrHigherForChunkedFile()
        {
            Assert.True(_service.CalculateConcurrency(chunkSizeInMB: 1) >= 1);
        }

        [Theory]
        [InlineData(0)]
        internal void CalculateConcurrencyThrowsForInvalidChunkSize(ushort chunkSize)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CalculateConcurrency(chunkSize));
        }
    }
}
