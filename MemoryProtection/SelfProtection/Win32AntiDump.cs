using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.SelfProtection
{
    /// <summary>
    /// Adaptation from https://github.com/Mecanik/Anti-DebugNET/tree/master/Anti-DebugNET/AntiDump. Doesn't seem to work as of .NET Core 3.1 :C
    /// </summary>
    internal static class Win32AntiDump
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualProtect(IntPtr lpAddress, IntPtr dwSize, IntPtr flNewProtect, ref IntPtr lpflOldProtect);

        private static void EraseSection(IntPtr address, int size)
        {
            IntPtr sz = (IntPtr)size;
            IntPtr dwOld = default;
            VirtualProtect(address, sz, (IntPtr)0x40, ref dwOld);
            Marshal.Copy(new byte[4096], 0, address, size);
            IntPtr temp = default;
            VirtualProtect(address, sz, dwOld, ref temp);
        }

        /// <summary>
        /// WARNING! It breaks applications which are obfuscated.
        /// </summary>
        public static void AntiDump()
        {
            var process = System.Diagnostics.Process.GetCurrentProcess();
            var base_address = process.MainModule.BaseAddress;
            var dwpeheader = Marshal.ReadInt32((IntPtr)(base_address.ToInt64() + 0x3C));
            var wnumberofsections = Marshal.ReadInt16((IntPtr)(base_address.ToInt64() + dwpeheader + 0x6));

            EraseSection(base_address, 30);

            for (int i = 0; i < peheaderdwords.Length; i++)
            {
                EraseSection((IntPtr)(base_address.ToInt64() + dwpeheader + peheaderdwords[i]), 4);
            }

            for (int i = 0; i < peheaderwords.Length; i++)
            {
                EraseSection((IntPtr)(base_address.ToInt64() + dwpeheader + peheaderwords[i]), 2);
            }

            for (int i = 0; i < peheaderbytes.Length; i++)
            {
                EraseSection((IntPtr)(base_address.ToInt64() + dwpeheader + peheaderbytes[i]), 1);
            }

            int x = 0;
            int y = 0;

            while (x <= wnumberofsections)
            {
                if (y == 0)
                {
                    EraseSection((IntPtr)(base_address.ToInt64() + dwpeheader + 0xFA + (0x28 * x) + 0x20), 2);
                }

                EraseSection((IntPtr)(base_address.ToInt64() + dwpeheader + 0xFA + (0x28 * x) + sectiontabledwords[y]), 4);

                y++;

                if (y == sectiontabledwords.Length)
                {
                    x++;
                    y = 0;
                }
            }
        }

        private static readonly int[] sectiontabledwords = new int[] { 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x24 };
        private static readonly int[] peheaderbytes = new int[] { 0x1A, 0x1B };
        private static readonly int[] peheaderwords = new int[] { 0x4, 0x16, 0x18, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x5C, 0x5E };
        private static readonly int[] peheaderdwords = new int[] { 0x0, 0x8, 0xC, 0x10, 0x16, 0x1C, 0x20, 0x28, 0x2C, 0x34, 0x3C, 0x4C, 0x50, 0x54, 0x58, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x11C };
    }
}
