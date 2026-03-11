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
        private readonly FakeVaultSession _session = FakeVaultSession.EmptyMockSession();

        public SystemServiceTests()
        {
            _service = new VaultCrypt.Services.SystemService(_session);
        }

        [Fact]
        void CheckFreeSpaceDoesNotThrowForValidValues()
        {
            var path = Path.GetTempPath();
            _service.CheckFreeSpace(NormalizedPath.From(path));
        }

        [Fact]
        void CheckFreeSpaceThrowsForInvalidValues()
        {
            var path = Path.GetTempPath();
            _session.VAULTPATH = NormalizedPath.From("WRONG VALUE");

            Assert.Throws<ArgumentException>(() => _service.CheckFreeSpace(NormalizedPath.From(path)));
            Assert.Throws<ArgumentException>(() => _service.CheckFreeSpace(NormalizedPath.From(string.Empty)));
        }

        [Fact]
        void CheckFreeSpaceThrowsForNullValues()
        {
            Assert.Throws<ArgumentNullException>(() => _service.CheckFreeSpace(null!));
        }

        [Fact]
        void CalculateConcurrencyReturnsOneForNonChunkedFile()
        {
            Assert.Equal(1, _service.CalculateConcurrency(false, 1));
        }

        [Fact]
        void CalculateConcurrencyOneOrHigherForChunkedFile()
        {
            Assert.True(_service.CalculateConcurrency(true, 1) >= 1);
        }

        [Fact]
        void CalculateConcurrencyThrowsForZeroValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _service.CalculateConcurrency(false, 0));
        }

        

    }
}
