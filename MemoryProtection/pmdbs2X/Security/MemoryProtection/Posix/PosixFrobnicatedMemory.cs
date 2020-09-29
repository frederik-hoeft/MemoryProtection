using pmdbs2X.Security.Unmanaged;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace pmdbs2X.Security.MemoryProtection.Posix
{
    public class PosixFrobnicatedMemory : ProtectedMemory
    {
        [DllImport("libc", SetLastError = true, PreserveSig = false)]
        private static extern void memfrob(IntPtr handle, uint n);

        public PosixFrobnicatedMemory(int size)
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
            Size = size;
            directHandle = Marshal.AllocHGlobal(size);
            MarshalExtensions.ZeroMemory(directHandle, size);
            Protect();
        }

        public override void Free()
        {
            MarshalExtensions.ZeroFree(directHandle, Size);
        }

        public override void Protect()
        {
            memfrob(directHandle, (uint)Size);
        }

        public override byte[] Read(int offset, int length)
        {
            Unprotect();
            byte[] bytes = new byte[length];
            Marshal.Copy(directHandle + offset, bytes, 0, length);
            Protect();
            return bytes;
        }

        public override void Unprotect()
        {
            memfrob(directHandle, (uint)Size);
        }
    }
}
