using MemoryProtection.SelfProtection.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.SelfProtection.MemoryProtection.Win32
{
    public class Win32EncryptedMemory : ProtectedMemory
    {
        private const uint CRYPTPROTECTMEMORY_BLOCK_SIZE = 16;

        private const uint CRYPTPROTECTMEMORY_SAME_PROCESS = 0x0;
        private const uint CRYPTPROTECTMEMORY_CROSS_PROCESS = 0x1;
        private const uint CRYPTPROTECTMEMORY_SAME_LOGON = 0x2;

        [DllImport("Crypt32.dll", SetLastError = true, PreserveSig = false)]
        private static extern bool CryptProtectMemory(IntPtr pDataIn, uint cbDataIn, uint dwFlags);

        [DllImport("Crypt32.dll", SetLastError = true, PreserveSig = false)]
        private static extern bool CryptUnprotectMemory(IntPtr pDataIn, uint cbDataIn, uint dwFlags);

        [DllImport("Kernel32.dll")]
        private static extern uint GetLastError();

        public Win32EncryptedMemory(int size)
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
            uint requiredBlocks = (uint)Math.Ceiling((double)size / CRYPTPROTECTMEMORY_BLOCK_SIZE);
            Size = (int)(requiredBlocks * CRYPTPROTECTMEMORY_BLOCK_SIZE);
            Handle = Marshal.AllocHGlobal(Size);
            MarshalExtensions.ZeroMemory(Handle, Size);
            Protect();
        }

        public override void Free()
        {
            Unprotect();
            MarshalExtensions.ZeroMemory(Handle, Size);
            Marshal.FreeHGlobal(Handle);
        }

        public override void Protect()
        {
            CryptProtectMemory(Handle, (uint)Size, CRYPTPROTECTMEMORY_SAME_PROCESS);
        }

        public override byte[] Read(int offset, int length)
        {
            Unprotect();
            byte[] bytes = new byte[length];
            Marshal.Copy(Handle + offset, bytes, 0, length);
            Protect();
            return bytes;
        }

        public override void Unprotect()
        {
            CryptUnprotectMemory(Handle, (uint)Size, CRYPTPROTECTMEMORY_SAME_PROCESS);
        }
    }
}
