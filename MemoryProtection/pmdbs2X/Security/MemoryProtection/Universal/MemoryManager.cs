using System;
using System.Collections.Generic;
using System.Text;

namespace MemoryProtection.pmdbs2X.Security.MemoryProtection.Universal
{
    internal static class MemoryManager
    {
        private static unsafe Dictionary<IntPtr, byte[]> Keys = new Dictionary<IntPtr, byte[]>();
        internal static void EncryptMemory(IntPtr handle, uint size)
        {
        }

        internal static void DecryptMemory(IntPtr handle, uint size)
        {
        }
    }
}
