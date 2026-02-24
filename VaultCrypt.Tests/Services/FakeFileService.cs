using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.Tests.Services
{
    public class FakeFileService : IFileService
    {
        public bool CopyPartOfFileWasCalled = false;
        public bool WriteReadyChunkWasCalled = false;
        public bool ZeroOutPartOfFileWasCalled = false;
        public void CopyPartOfFile(Stream source, long offset, ulong length, Stream destination, long destinationOffset) => CopyPartOfFileWasCalled = true;

        public void WriteReadyChunk(ConcurrentDictionary<int, byte[]> results, ref int nextToWrite, int currentIndex, Stream fileFS, object lockObject) => WriteReadyChunkWasCalled = true;

        public void ZeroOutPartOfFile(Stream stream, long offset, ulong length) => ZeroOutPartOfFileWasCalled = true;
    }
}
