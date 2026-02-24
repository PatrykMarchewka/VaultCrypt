using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.Tests.Services
{
    internal class FakeDecryptionService : IDecryptionService
    {
        public bool DecryptWasCalled = false;
        public Task Decrypt(long metadataOffset, NormalizedPath filePath, ProgressionContext context)
        {
            DecryptWasCalled = true;
            return Task.CompletedTask;
        }
    }
}
