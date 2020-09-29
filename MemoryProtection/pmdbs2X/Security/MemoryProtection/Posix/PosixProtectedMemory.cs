using pmdbs2X.Security.Unmanaged;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace pmdbs2X.Security.MemoryProtection.Posix
{
    public class PosixProtectedMemory : ProtectedMemory
    {
        [DllImport("libc", SetLastError = true, PreserveSig = false)]
        private static extern int mprotect(IntPtr addr, uint len, int prot);

        [DllImport("libc", SetLastError = true, PreserveSig = false)]
        private static extern int getpagesize();

        [DllImport("libc", SetLastError = true, PreserveSig = false)]
        private static extern long sysconf(int name);

        [DllImport("libc", SetLastError = true, PreserveSig = false)]
        private static extern unsafe int posix_memalign(void** memptr, uint alignment, uint size);

        [DllImport("libc", SetLastError = true, PreserveSig = false)]
        private static extern void free(IntPtr ptr);

        private const int _SC_PAGESIZE = 47;

        private readonly uint allocatedSize;
        public unsafe PosixProtectedMemory(int size)
        {
            if (size < 0)
            {
                throw new ArgumentException("Fatal: cannot allocate less than zero.");
            }
            ContentLength = size;
            if (size == 0)
            {
                size = 1;
            }
            uint pageSize = (uint)getpagesize();
            if (pageSize == 0x0)
            {
                Debug.WriteLine("getpagesize() returned 0! Defaulting to 4096 Bytes ...");
                pageSize = 4096;
            }
            uint requiredPages = (uint)Math.Ceiling((double)size / pageSize);
            allocatedSize = requiredPages * pageSize;
            Size = (int)allocatedSize;
            void* memptr = null;
            _ = posix_memalign(&memptr, pageSize, allocatedSize);
            directHandle = (IntPtr)memptr;
            MarshalExtensions.ZeroMemory(directHandle, Size);
            ContentLength = size;
            _ = mprotect(directHandle, allocatedSize, (int)PROT_FLAGS.PROT_NONE);
        }

        public override void Free()
        {
            Unprotect();
            MarshalExtensions.ZeroMemory(directHandle, Size);
            free(directHandle);
        }

        public override void Protect()
        {
            _ = mprotect(directHandle, (uint)Size, (int)PROT_FLAGS.PROT_NONE);
        }

        public override byte[] Read(int offset, int length)
        {
            _ = mprotect(directHandle, (uint)Size, (int)PROT_FLAGS.PROT_READ);
            byte[] bytes = new byte[length];
            Marshal.Copy(directHandle + offset, bytes, 0, length);
            Protect();
            return bytes;
        }

        public override void Unprotect()
        {
            _ = mprotect(directHandle, (uint)Size, (int)(PROT_FLAGS.PROT_WRITE | PROT_FLAGS.PROT_READ));
        }

        [Flags]
        private enum PROT_FLAGS
        {
            /* Page can not be accessed.  */
            PROT_NONE = 0x0,
            /* Page can be read.  */
            PROT_READ = 0x1,
            /* Page can be written.  */
            PROT_WRITE = 0x2,
            /* Page can be executed.  */
            PROT_EXEC = 0x4,
        }
    }
}
