using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using static VaultCrypt.SecureBuffer;

namespace VaultCrypt
{
    public sealed unsafe class SecureUnmanagedMemoryManager : MemoryManager<byte>
    {
        private byte* _pointer;
        private int _length;
        private int _disposed; //0 = alive, 1 = disposed, any other value should be treated as an error. Required to be int to use with Interlocked for atomic operation

        public SecureUnmanagedMemoryManager(byte* pointer, int length)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

            _pointer = pointer;
            _length = length;
        }

        public SecureUnmanagedMemoryManager(void* pointer, int length) : this((byte*)pointer, length)
        {

        }
        /// <summary>
        /// Creates new span over the target pointer
        /// </summary>
        /// <returns>Span over the memory</returns>
        /// <exception cref="ObjectDisposedException">Thrown when the object is marked as already disposed</exception>
        public override Span<byte> GetSpan()
        {
            //Volatile read to ensure that Main and GC threads dont overlap and read wrong value
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, nameof(SecureLargeBuffer));
            return new Span<byte>(_pointer, _length);
        }

        /// <summary>
        /// Returns handle to memory at specified offset
        /// </summary>
        /// <param name="elementIndex">Offset in bytes from the start of the memory</param>
        /// <returns>Memory handle struct holding the pointer with the added <paramref name="elementIndex"/> offset</returns>
        /// <exception cref="ObjectDisposedException">Thrown when the object is marked as already disposed</exception>
        public override MemoryHandle Pin(int elementIndex = 0){
            //Volatile read to ensure that Main and GC threads dont overlap and read wrong value
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, nameof(SecureLargeBuffer));
            return new MemoryHandle(_pointer + elementIndex);
        }

        /// <summary>
        /// Unmanaged memory is outisde GC heap, this method does nothing in this context
        /// </summary>
        public override void Unpin()
        {
            //Unmanaged memory is outside GC heap, method intentionally left empty
        }

        protected override void Dispose(bool disposing)
        {
            //Unamanaged memory should be freed from where it is managed instead
            Interlocked.Exchange(ref _disposed, 1);
            _pointer = null;
            _length = 0;
        }
    }
}
