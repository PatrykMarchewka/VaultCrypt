using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.Tests.Services
{
    internal class FakeEncryptionService : IEncryptionService
    {
        public bool EncryptWasCalled = false;
        public Task Encrypt(EncryptionAlgorithm.EncryptionAlgorithmInfo algorithm, ushort chunkSizeInMB, NormalizedPath filePath, ProgressionContext context)
        {
            EncryptWasCalled = true;
            return Task.CompletedTask;
        }
    }
}
