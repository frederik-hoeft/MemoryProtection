using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.SelfProtection.MemoryProtection.Linux
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
            Console.WriteLine("getpagesize returned " + pageSize.ToString());
            if (pageSize == 0x0)
            {
                Console.WriteLine("That's invalid. Bye!");
                Environment.Exit(-1337);
            }
            uint requiredPages = (uint)Math.Ceiling((double)size / pageSize);
            allocatedSize = requiredPages * pageSize;
            Size = (int)allocatedSize;
            void* memptr = null;
            int ret = posix_memalign(&memptr, pageSize, allocatedSize);
            Console.WriteLine("posix_memalign returned 0x" + ret.ToString("x"));
            Console.WriteLine("memptr is 0x" + ((ulong)memptr).ToString("x"));
            Handle = (IntPtr)memptr;
            MarshalExtensions.ZeroMemory(Handle, Size);
            Console.WriteLine("Zeroed memory!");
            ContentLength = size;
            ret = mprotect(Handle, allocatedSize, (int)PROT_FLAGS.PROT_NONE);
            Console.WriteLine("mprotect returned 0x" + ret.ToString("x"));
        }

        public override void Free()
        {
            Unprotect();
            MarshalExtensions.ZeroMemory(Handle, Size);
            free(Handle);
        }

        public override void Protect()
        {
            _ = mprotect(Handle, (uint)Size, (int)PROT_FLAGS.PROT_NONE);
        }

        public override byte[] Read(int offset, int length)
        {
            _ = mprotect(Handle, (uint)Size, (int)PROT_FLAGS.PROT_READ);
            byte[] bytes = new byte[length];
            Marshal.Copy(Handle + offset, bytes, 0, length);
            Protect();
            return bytes;
        }

        public override void Unprotect()
        {
            _ = mprotect(Handle, (uint)Size, (int)(PROT_FLAGS.PROT_WRITE | PROT_FLAGS.PROT_READ));
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
