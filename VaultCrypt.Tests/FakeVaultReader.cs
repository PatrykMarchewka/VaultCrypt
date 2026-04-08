using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class FakeVaultReader : IVaultReader
    {
        public bool AddAndSaveMetadataOffsetsWasCalled = false;
        public bool PopulateEncryptedFilesListWasCalled = false;
        public bool PrepareVaultHeaderWasCalled = false;
        public bool ReadAndDecryptMetadataWasCalled = false;
        public bool ReadIterationsNumberWasCalled = false;
        public bool ReadMetadataOffsetsWasCalled = false;
        public bool ReadSaltWasCalled = false;
        public bool RemoveAndSaveMetadataOffsetsWasCalled = false;
        public bool SaveMetadataOffsetsWasCalled = false;
        public bool VaultEncryptionWasCalled = false;


        public byte Version => byte.MaxValue;

        public byte VaultEncryptionAlgorithm => 0;

        public ushort SaltSize => 1;

        public ushort EncryptionOptionsSize => 2;

        public ushort MetadataOffsetsSize => 3;

        public ushort HeaderSize => 4;

        public void AddAndSaveMetadataOffsets(Stream stream, long newOffset) => AddAndSaveMetadataOffsetsWasCalled = true;

        public void PopulateEncryptedFilesList(Stream stream) => PopulateEncryptedFilesListWasCalled = true;

        public SecureBuffer.SecureLargeBuffer PrepareVaultHeader(ReadOnlySpan<byte> salt, int iterations)
        {
            PrepareVaultHeaderWasCalled = true;
            return null!;
        }

        public SecureBuffer.SecureLargeBuffer ReadAndDecryptData(Stream stream, long offset, int length)
        {
            ReadAndDecryptMetadataWasCalled = true;
            return null!;
        }

        public int ReadIterationsNumber(Stream stream)
        {
            ReadIterationsNumberWasCalled = true;
            return 0;
        }

        public long[] ReadMetadataOffsets(Stream stream)
        {
            ReadMetadataOffsetsWasCalled = true;
            return new long[0];
        }

        public SecureBuffer.SecureLargeBuffer ReadSalt(Stream stream)
        {
            ReadSaltWasCalled = true;
            return null!;
        }

        public void RemoveAndSaveMetadataOffsets(Stream stream, ushort itemIndex) => RemoveAndSaveMetadataOffsetsWasCalled = true;

        public void SaveMetadataOffsets(Stream stream, long[] offsets) => SaveMetadataOffsetsWasCalled = true;

        public SecureBuffer.SecureLargeBuffer VaultEncryption(ReadOnlyMemory<byte> data)
        {
            VaultEncryptionWasCalled = true;
            return null!;
        }
    }
}
