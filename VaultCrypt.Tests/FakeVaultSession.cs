using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.Tests
{
    public class FakeVaultSession : IVaultSession
    {
        public bool CreateSessionWasCalled = false;
        public bool RaiseEncryptedFileListUpdatedWasCalled = false;
        private FakeVaultSession() { }

        public static FakeVaultSession EmptyMockSession()
        {
            FakeVaultSession session = new();
            session.KEY = new byte[4] { 0, 1, 0, 255 };
            session.VAULTPATH = NormalizedPath.From("C:\\FakeVaultSession\\");
            session.ENCRYPTED_FILES = new()
            {
                {0, new EncryptedFileInfo(null, 0, null) },
                {1, new EncryptedFileInfo("TEST", 123, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0]) },
                {long.MaxValue, new EncryptedFileInfo("MAX", ulong.MaxValue, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[1]) }
            };
            var registry = new VaultRegistry(null!, null!);
            session.VAULT_READER = VaultRegistry.GetVaultReader(0);

            return session;
        }

        public static FakeVaultSession FilledMockSession(IEncryptionOptionsService encryptionOptionsService, byte vaultVersion = 0, byte[]? key = null, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null)
        {
            FakeVaultSession session = new();
            session.KEY = key ??= new byte[2] { 0, 1 };
            session.VAULTPATH = vaultPath ??= NormalizedPath.From("D:\\FakeVaultSession\\");
            session.ENCRYPTED_FILES = encryptedFiles ??= new()
            {
                {0, new EncryptedFileInfo(null, 0, null) },
                {1, new EncryptedFileInfo("video.mkv", 1_234_567, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0]) },
                {1010, new EncryptedFileInfo("file.txt", 1, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[1]) }
            };
            var registry = new VaultRegistry(session, encryptionOptionsService);
            session.VAULT_READER = VaultRegistry.GetVaultReader(vaultVersion);

            return session;
        }


        public byte[] KEY { get; set; }

        public NormalizedPath VAULTPATH { get; set; }

        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; set; }

        public VaultReader VAULT_READER { get; set; }

        public event Action? EncryptedFilesListUpdated;

        public void CreateSession(NormalizedPath vaultPath, VaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations) => CreateSessionWasCalled = true;

        public void RasiseEncryptedFileListUpdated() => RaiseEncryptedFileListUpdatedWasCalled = true;
    }
}
