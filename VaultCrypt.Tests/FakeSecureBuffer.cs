using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class FakeSecureBuffer : ISecureBuffer
    {
        public bool LengthWasCalled = false;
        public bool AsSpanWasCalled = false;
        public bool AsMemoryWasCalled = false;
        public bool DisposeWasCalled = false;
        private bool Empty;
        
        /// <summary>
        /// Creates <see cref="ISecureBuffer"/> mock to use in tests
        /// </summary>
        /// <param name="empty">Indicates whether it should return invalid empty buffer with Span size set to 0 or valid with 1 byte</param>
        public FakeSecureBuffer(bool empty)
        {
            Empty = empty;
        }

        private int GetLength()
        {
            LengthWasCalled = true;
            return 0;
        }

        private Span<byte> GetSpan()
        {
            AsSpanWasCalled = true;
            if (Empty) return Span<byte>.Empty;
            else return new byte[1];
        }

        private Memory<byte> GetMemory()
        {
            AsMemoryWasCalled = true;
            if (Empty) return Memory<byte>.Empty;
            else return new byte[1];
        }

        public int Length => GetLength();

        public Span<byte> AsSpan => GetSpan();

        public Memory<byte> AsMemory => GetMemory();

        public void Dispose()
        {
            DisposeWasCalled = true;
        }
    }
}
