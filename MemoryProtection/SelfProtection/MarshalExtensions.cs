using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;

namespace MemoryProtection.SelfProtection
{
    internal static class MarshalExtensions
    {
        internal static void ZeroMemory(IntPtr handle, int size)
        {
            byte[] zeros = new byte[size];
            Marshal.Copy(zeros, 0, handle, size);
        }

        internal static void Copy(IntPtr source, int sourceOffset, IntPtr destination, int destinationOffset, int length)
        {
            IntPtr s = source + sourceOffset;
            IntPtr d = destination + destinationOffset;
            for (int i = 0; i < length; i++)
            {
                byte b = Marshal.ReadByte(s + i);
                Marshal.WriteByte(d + i, b);
            }
        }
    }
}
