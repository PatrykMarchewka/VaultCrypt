using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    public interface ISecureBuffer
    {
        public int Length { get; }
        public Span<byte> AsSpan { get; }
    }


    public class SecureBuffer
    {
        /// <summary>
        /// Class to securely manage memory that is outside GC control and cannot be written as page file to disk
        /// <br/>
        /// Maximum lockable memory varies between OS version and system load: <br/>
        /// Windows: 1-8MB <br/>
        /// Linux: 32-64KB <br/>
        /// MacOS: 64-256KB <br/>
        /// For compatibility the buffer should not be created for memory over 32KB
        /// </summary>
        public unsafe class SecureKeyBuffer : ISecureBuffer, IDisposable
        {
            private void* _pointer;
            private int _disposed; //0 = alive, 1 = disposed, any other value should be treated as an error. Required to be int to use with Interlocked for atomic operation
            //Locked memory cannot be written to disk as page file.
            private int _locked; //0 = unlocked, 1 = locked, any other value should be treated as an error. Required to be int to use with Interlocked for atomic operation
            private int _length; //Length of the buffer, padded to match multiple of page size
            /// <summary>
            /// Gets full length of the buffer which is padded to match multiple of page size
            /// </summary>
            /// <exception cref="ObjectDisposedException">Thrown when the object is marked as already disposed</exception>
            public int Length
            {
                get
                {
                    ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, nameof(SecureKeyBuffer));
                    return _length;
                }
            }

            /// <summary>
            /// Creates a new span over memory region
            /// </summary>
            /// <exception cref="ObjectDisposedException">Thrown when the object is marked as already disposed</exception>
            public Span<byte> AsSpan
            {
                get
                {
                    //Volatile read to ensure that Main and GC threads dont overlap and read wrong value
                    ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, nameof(SecureKeyBuffer));
                    return new Span<byte>(_pointer, _length);
                }
            }

            /// <summary>
            /// Creates a secure page backed memory region that is zeroed and padded to match page size
            /// </summary>
            /// <param name="length">Size in bytes of requested memory region</param>
            /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="length"/> is set to negative value or zero</exception>
            /// <exception cref="PlatformNotSupportedException">Thrown when the OS is not Windows, Mac or Linux</exception>
            public SecureKeyBuffer(int length)
            {
                ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

                int pageSize = Environment.SystemPageSize;

                _length = ((length + pageSize - 1) / pageSize) * pageSize;

                if (OperatingSystem.IsWindows())
                {
                    _pointer = VirtualAlloc(null, (nuint)_length, AllocationType.MEM_RESERVE | AllocationType.MEM_COMMIT, Protect.PAGE_READWRITE);
                }
                else if(OperatingSystem.IsMacOS())
                {
                    _pointer = mmap(null, (nuint)_length, Protection.PROT_READ | Protection.PROT_WRITE, Flags.MAP_PRIVATE | Flags.MAP_ANONYMOUS_MAC);
                }
                else if (OperatingSystem.IsLinux())
                {
                    _pointer = mmap(null, (nuint)_length, Protection.PROT_READ | Protection.PROT_WRITE, Flags.MAP_PRIVATE | Flags.MAP_ANONYMOUS_LINUX);
                }
                else
                {
                    throw new PlatformNotSupportedException();
                }

                try
                {
                    LockMemory();
                    Interlocked.Exchange(ref _locked, 1);
                }
                catch
                {
                    //Locking failed, free memory and throw to avoid leaving sensitive data
                    ReleaseMemory();
                    _pointer = null;
                    throw;
                }
            }

            /// <summary>
            /// Locks memory in RAM
            /// </summary>
            /// <exception cref="SecurityException">Thrown when memory fails to be locked</exception>
            /// <exception cref="PlatformNotSupportedException">Thrown when the OS is not Windows, Mac or Linux</exception>
            private void LockMemory()
            {
                if (OperatingSystem.IsWindows())
                {
                    if (!VirtualLock(_pointer, (nuint)_length)) throw new SecurityException($"Error while locking memory on Windows: {Marshal.GetLastWin32Error()}");
                }
                else if(OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
                {
                    if (mlock(_pointer, (nuint)_length) != 0) throw new SecurityException($"Error while locking memory on Mac/Linux: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    throw new PlatformNotSupportedException();
                }
            }

            /// <summary>
            /// Unlocks locked memory
            /// </summary>
            /// <exception cref="SecurityException">Thrown when memory fails to be unlocked</exception>
            /// <exception cref="PlatformNotSupportedException">Thrown when the OS is not Windows, Mac or Linux</exception>
            private void UnlockMemory()
            {
                if (OperatingSystem.IsWindows())
                {
                    if (!VirtualUnlock(_pointer, (nuint)_length)) throw new SecurityException($"Error while unlocking memory on Windows: {Marshal.GetLastWin32Error()}");
                }
                else if (OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
                {
                    if (munlock(_pointer, (nuint)_length) != 0) throw new SecurityException($"Error while unlocking memory on Mac/Linux: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    throw new PlatformNotSupportedException();
                }
            }

            private void ReleaseMemory()
            {
                if (_pointer is null) return;
                try
                {
                    CryptographicOperations.ZeroMemory(new Span<byte>(_pointer, _length));
                    if(Interlocked.Exchange(ref _locked, 0) != 0) UnlockMemory();
                }
                finally
                {
                    if (OperatingSystem.IsWindows())
                    {
                        /*
                         * As required per Microsoft documentation: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
                         * "If you specify this value, dwSize must be 0 (zero), and lpAddress must point to the base address returned by the VirtualAlloc function when the region is reserved. The function fails if either of these conditions is not met."
                         */
                        VirtualFree(lpAddress: _pointer, dwSize: 0, FreeType.MEM_RELEASE);
                    }
                    else if(OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
                    {
                        munmap(_pointer, (nuint)_length);
                    }
                    else
                    {
                        throw new PlatformNotSupportedException();
                    }
                    _pointer = null;
                }
            }

            /// <summary>
            /// Safely releases memory by zeroing it, unlocking and finally freeing
            /// </summary>
            public void Dispose()
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
                GC.SuppressFinalize(this);
                ReleaseMemory();
            }

            ~SecureKeyBuffer()
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
                ReleaseMemory();
            }

            // P/Invoke

            // Taken from https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
            [SupportedOSPlatform("windows")]
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern void* VirtualAlloc(void* lpAddress, nuint dwSize, AllocationType flAllocationType, Protect flProtect);

            [Flags]
            enum AllocationType : uint
            {
                MEM_COMMIT = 0x00001000, //Allocates physical memory, requires pointer to be reserved
                MEM_RESERVE = 0x00002000, //Reserves the pointer for allocation
            }

            //Taken from https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants
            [Flags]
            enum Protect : uint
            {
                PAGE_READWRITE = 0x04, //Read and write privileges
            }

            //Taken from https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
            [SupportedOSPlatform("windows")]
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool VirtualFree(void* lpAddress, nuint dwSize, FreeType dwFreeType);

            enum FreeType : uint
            {
                MEM_RELEASE = 0x00008000 //Frees the memory completely, removing the reservation. Requires dwSize to be 0! 
            }


            //Taken from https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock
            [SupportedOSPlatform("windows")]
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool VirtualLock(void* lpAddress, nuint dwSize);

            //Taken from https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualunlock
            [SupportedOSPlatform("windows")]
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool VirtualUnlock(void* lpAddress, nuint dwSize);

            //Taken from https://www.man7.org/linux/man-pages/man2/mlock.2.html
            [SupportedOSPlatform("linux"), SupportedOSPlatform("macos")]
            [DllImport("libc", SetLastError = true)]
            private static extern int mlock(void* addr, nuint len);

            //Taken from https://man7.org/linux/man-pages/man2/munlock.2.html
            [SupportedOSPlatform("linux"), SupportedOSPlatform("macos")]
            [DllImport("libc", SetLastError = true)]
            private static extern int munlock(void* addr, nuint len);

            //Taken from https://www.man7.org/linux/man-pages/man2/mmap.2.html
            [SupportedOSPlatform("linux"), SupportedOSPlatform("macos")]
            [DllImport("libc", SetLastError = true)]
            private static extern void* mmap(void* addr, nuint len, Protection protection, Flags flags, int fd = -1, int offset = 0);

            //Taken from https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/mman-common.h
            [Flags]
            enum Protection : int
            {
                PROT_READ = 0x1, //Read privileges
                PROT_WRITE = 0x2 //Write privileges
            }

            //Mac flag taken from https://github.com/apple/darwin-xnu/blob/main/bsd/sys/mman.h
            [Flags]
            enum Flags : int
            {
                MAP_PRIVATE = 0x2, //Private mapping not visible to other processes
                MAP_ANONYMOUS_LINUX = 0x20, //Zero initialized page, not backed by a file. Linux only
                MAP_ANONYMOUS_MAC = 0x1000 //Zero initialized page, not backed by a file. Mac/BSD only
            }

            //Taken from https://man7.org/linux/man-pages/man3/munmap.3p.html
            [SupportedOSPlatform("linux"), SupportedOSPlatform("macos")]
            [DllImport("libc", SetLastError = true)]
            private static extern int munmap(void* addr, nuint len);

        }

        /// <summary>
        /// Class to securely manage memory that is outside GC control, intended for memory above 32KB
        /// </summary>
        public unsafe class SecureLargeBuffer : ISecureBuffer, IDisposable
        {
            private void* _pointer;
            private int _disposed; //0 = alive, 1 = disposed, any other value should be treated as an error. Required to be int to use with Interlocked for atomic operation
            private int _length;
            /// <summary>
            /// Gets full length of the buffer
            /// </summary>
            /// <exception cref="ObjectDisposedException">Thrown when the object is marked as already disposed</exception>
            public int Length
            {
                get
                {
                    ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, nameof(SecureLargeBuffer));
                    return _length;
                }
            }

            /// <summary>
            /// Creates a new span over memory region
            /// </summary>
            /// <exception cref="ObjectDisposedException">Thrown when the object is marked as already disposed</exception>
            public Span<byte> AsSpan
            {
                get
                {
                    //Volatile read to ensure that Main and GC threads dont overlap and read wrong value
                    ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, nameof(SecureLargeBuffer));
                    return new Span<byte>(_pointer, _length);
                }
            }

            /// <summary>
            /// Creates a new instance of <see cref="SecureUnmanagedMemoryManager"/> and returns memory block
            /// </summary>
            /// <exception cref="ObjectDisposedException">Thrown when the object is marked as already disposed</exception>
            public Memory<byte> AsMemory
            {
                get
                {
                    //Volatile read to ensure that Main and GC threads dont overlap and read wrong value
                    ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, nameof(SecureKeyBuffer));
                    return new SecureUnmanagedMemoryManager(_pointer, _length).Memory;
                }
            }

            /// <summary>
            /// Creates new block of zeroed and unpinned memory
            /// </summary>
            /// <param name="length">Size in bytes of memory to create</param>
            /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="length"/> is set to negative or zero value</exception>
            public SecureLargeBuffer(int length)
            {
                ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

                _length = length;
                _pointer = NativeMemory.AllocZeroed((nuint)length);
            }

            /// <summary>
            /// Zeroes and frees the memory
            /// </summary>
            private void ReleaseMemory()
            {
                if (_pointer is null) return;
                try
                {
                    CryptographicOperations.ZeroMemory(new Span<byte>(_pointer, _length));
                }
                finally
                {
                    NativeMemory.Free(_pointer);
                    _pointer = null;
                    _length = 0;
                }
            }

            /// <summary>
            /// Disposes unmanaged objects and optionally managed ones
            /// </summary>
            /// <param name="disposing">Indicating whether to dispose managed objects</param>
            void Dispose(bool disposing)
            {
                //Atomic write to ensure that Main and GC threads dont overlap and read wrong value
                if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
                ReleaseMemory();
            }

            /// <summary>
            /// Safely releases memory by zeroing it and freeing
            /// </summary>
            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }
            ~SecureLargeBuffer()
            {
                Dispose(false);
            }
        }
    }
}
