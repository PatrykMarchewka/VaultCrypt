using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.Tests.Services
{
    internal class FakeVaultService : IVaultService
    {
        public bool CreateVaultWasCalled = false;
        public void CreateVault(NormalizedPath folderPath, string vaultName, byte[] password, int iterations) => CreateVaultWasCalled = true;
    }
}
