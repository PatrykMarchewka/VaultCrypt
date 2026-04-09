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
        public bool GetSlicedKeyWasCalled = false;
        public bool DisposeWasCalled = false;
        private FakeVaultSession() { }

        public static FakeVaultSession EmptyMockSession()
        {
            FakeVaultSession session = new();
            SecureBuffer.SecureKeyBuffer keyBuffer = new SecureBuffer.SecureKeyBuffer(PasswordHelper.KeySize);
            byte[] key = new byte[4] { 0, 1, 0, 255 };
            key.CopyTo(keyBuffer.AsSpan);
            session.KEY = keyBuffer;
            session.VAULTPATH = NormalizedPath.From("C:\\FakeVaultSession\\");
            session.ENCRYPTED_FILES = new()
            {
                {0, new EncryptedFileInfo(null, 0, null) },
                {1, new EncryptedFileInfo("TEST", 123, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0]) },
                {long.MaxValue, new EncryptedFileInfo("MAX", ulong.MaxValue, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[1]) }
            };
            session.VAULT_READER = new FakeVaultReader();

            return session;
        }

        public static FakeVaultSession FilledMockSession(IEncryptionOptionsService encryptionOptionsService, byte vaultVersion = 0, SecureBuffer.SecureKeyBuffer? key = null, NormalizedPath? vaultPath = null, Dictionary<long, EncryptedFileInfo>? encryptedFiles = null)
        {
            FakeVaultSession session = new();
            SecureBuffer.SecureKeyBuffer keyBuffer = new SecureBuffer.SecureKeyBuffer(PasswordHelper.KeySize);
            byte[] keyBytes = new byte[4] { 0, 1, 0, 255 };
            keyBytes.CopyTo(keyBuffer.AsSpan);
            session.KEY = key ??= keyBuffer;
            session.VAULTPATH = vaultPath ??= NormalizedPath.From("D:\\FakeVaultSession\\");
            session.ENCRYPTED_FILES = encryptedFiles ??= new()
            {
                {0, new EncryptedFileInfo(null, 0, null) },
                {1, new EncryptedFileInfo("video.mkv", 1_234_567, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0]) },
                {1010, new EncryptedFileInfo("file.txt", 1, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[1]) }
            };
            session.VAULT_READER = new FakeVaultReader();

            return session;
        }


        public SecureBuffer.SecureKeyBuffer KEY { get; set; }

        public NormalizedPath VAULTPATH { get; set; }

        public Dictionary<long, EncryptedFileInfo> ENCRYPTED_FILES { get; set; }

        public IVaultReader VAULT_READER { get; set; }

        public event Action? EncryptedFilesListUpdated;

        public void CreateSession(NormalizedPath vaultPath, IVaultReader vaultReader, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations) => CreateSessionWasCalled = true;

        public void RaiseEncryptedFileListUpdated() => RaiseEncryptedFileListUpdatedWasCalled = true;

        public ReadOnlySpan<byte> GetSlicedKey(byte keySize)
        {
            GetSlicedKeyWasCalled = true;
            return new byte[0];
        }

        public void Dispose() => DisposeWasCalled = true;
    }
}
