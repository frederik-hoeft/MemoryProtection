﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Text;

namespace MemoryProtection.SelfProtection.MemoryProtection.Win32
{
    public class Win32ProtectedMemory : ProtectedMemory
    {
        [DllImport("kernel32.dll", SetLastError = true, PreserveSig = false)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, PreserveSig = false)]
        private static extern void GetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);

        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;

        private readonly UIntPtr pUsableSize;
        private readonly int allocatedSize;
        public Win32ProtectedMemory(int size)
        {
            if (size < 1)
            {
                throw new ArgumentException("Fatal: cannot allocate less than one byte.");
            }
            GetNativeSystemInfo(out SYSTEM_INFO systemInfo);
            uint pageSize = systemInfo.dwPageSize;
            uint requiredPages = (uint)Math.Ceiling((double)size / pageSize);
            allocatedSize = (int)((requiredPages + 2) * pageSize);
            Size = (int)(requiredPages * pageSize);
            pUsableSize = new UIntPtr((uint)Size);
            rawHandle = Marshal.AllocHGlobal(allocatedSize);
            Handle = rawHandle + (int)pageSize;
            MarshalExtensions.ZeroMemory(Handle, Size);
            ContentLength = size;
            Protect();
        }

        public override byte[] Read(int offset, int length)
        {
            VirtualProtect(Handle, pUsableSize, PAGE_READONLY, out _);
            byte[] bytes = new byte[length];
            Marshal.Copy(Handle + offset, bytes, 0, length);
            Protect();
            return bytes;
        }

        public override void Free()
        {
            Unprotect();
            MarshalExtensions.ZeroMemory(Handle, Size);
            Marshal.FreeHGlobal(rawHandle);
        }

        public override void Protect()
        {
            VirtualProtect(Handle, pUsableSize, PAGE_NOACCESS, out _);
        }

        public override void Unprotect()
        {
            VirtualProtect(Handle, pUsableSize, PAGE_READWRITE, out _);
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct DUMMYUNIONNAME
        {
            [FieldOffset(0)] internal uint dwOemId;
            [FieldOffset(0)] internal ushort wProcessorArchitecture;
            [FieldOffset(sizeof(ushort))] internal ushort wReserved;
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_INFO
        {
            internal DUMMYUNIONNAME DUMMYUNIONNAME;
            internal uint dwPageSize;
            internal IntPtr lpMinimumApplicationAddress;
            internal IntPtr lpMaximumApplicationAddress;
            internal IntPtr dwActiveProcessorMask;
            internal uint dwNumberOfProcessors;
            internal uint dwProcessorType;
            internal uint dwAllocationGranularity;
            internal ushort wProcessorLevel;
            internal ushort wProcessorRevision;
        }
    }
}
