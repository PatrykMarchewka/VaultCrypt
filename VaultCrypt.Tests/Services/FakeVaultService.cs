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
        public bool CreateSessionFromFileWasCalled = false;
        public bool CreateVaultWasCalled = false;
        public bool DeleteFileFromVaultWasCalled = false;
        public bool RefreshEncryptedFilesListWasCalled = false;
        public bool TrimVaultWasCalled = false;

        public void CreateSessionFromFile(ReadOnlySpan<byte> password, NormalizedPath path) => CreateSessionFromFileWasCalled = true;

        public void CreateVault(NormalizedPath folderPath, string vaultName, ReadOnlySpan<byte> password, int iterations) => CreateVaultWasCalled = true;

        public void DeleteFileFromVault(long offset, ProgressionContext context) => DeleteFileFromVaultWasCalled = true;

        public void RefreshEncryptedFilesList(Stream vaultFS) => RefreshEncryptedFilesListWasCalled = true;

        public void TrimVault(ProgressionContext context) => TrimVaultWasCalled = true;
    }
}
