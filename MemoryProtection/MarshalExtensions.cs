using MemoryProtection.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;

namespace MemoryProtection
{
    internal static class MarshalExtensions
    {
        internal static void ZeroMemory(IntPtr handle, int size)
        {
            byte[] zeros = new byte[size];
            Marshal.Copy(zeros, 0, handle, size);
        }

        internal static void ZeroFree(IntPtr handle, int size)
        {
            ZeroMemory(handle, size);
            Marshal.FreeHGlobal(handle);
        }

        internal static void Copy(IntPtr source, int sourceOffset, IntPtr destination, int destinationOffset, int length)
        {
            IntPtr s = source + sourceOffset;
            IntPtr d = destination + destinationOffset;
            if ((length & 1) == 1)
            {
                for (int i = 0; i < length; i++)
                {
                    byte b = Marshal.ReadByte(s + i);
                    Marshal.WriteByte(d + i, b);
                }
            }
            else
            {
                for (int i = 0; i < (length / 2); i++)
                {
                    short b = Marshal.ReadInt16(s + (2 * i));
                    Marshal.WriteInt16(d + (2 * i), b);
                }
            }
        }

        internal static void Copy(uint[] source, int startIndex, IntPtr destination, int length)
        {
            byte[] buffer = new byte[length * sizeof(uint)];
            Buffer.BlockCopy(source, startIndex, buffer, 0, length);
            Marshal.Copy(buffer, 0, destination, length);
        }

        internal static unsafe void Copy(uint[] source, int startIndex, uint* destination, int length)
        {
            for (int i = 0; i < length; i++)
            {
                destination[i] = source[i + startIndex];
            }
        }

        internal static void CopyWithBuffer(IntPtr source, int sourceOffset, IntPtr destination, int destinationOffset, int length, IntPtr buffer)
        {
            Copy(source, sourceOffset, buffer, 0, length);
            Copy(buffer, 0, destination, destinationOffset, length);
        }

        internal static short ReadInt16BigEndian(IntPtr ptr)
        {
            byte[] bytes = new byte[2];
            Marshal.Copy(ptr, bytes, 0, 2);
            short hi = (short)(bytes[0] << 8);
            short lo = bytes[1];
            return (short)(hi + lo);
        }

        internal static void WriteInt32BigEndian(IntPtr ptr, int val)
        {
            byte[] bytes = new byte[4];
            bytes[0] = (byte)(val >> 24);
            bytes[1] = (byte)(val >> 16);
            bytes[2] = (byte)(val >> 8);
            bytes[3] = (byte)val;
            Marshal.Copy(bytes, 0, ptr, 4);
        }

        internal static unsafe void WriteInt32BigEndian(byte* buffer, int val)
        {
            buffer[0] = (byte)(val >> 24);
            buffer[1] = (byte)(val >> 16);
            buffer[2] = (byte)(val >> 8);
            buffer[3] = (byte)val;
        }

        internal static int ReadInt32BigEndian(IntPtr ptr)
        {
            return (Marshal.ReadByte(ptr) << 24) + (Marshal.ReadByte(ptr + 1) << 16) + (Marshal.ReadByte(ptr + 2) << 8) + Marshal.ReadByte(ptr + 3);
        }

        internal static void Int32LittleEndianArrayToBigEndian(IntPtr ptr, int size)
        {
            for (int i = 0; i < size / sizeof(int); i++)
            {
                int value = Marshal.ReadInt32(ptr + (i * sizeof(int)));
                WriteInt32BigEndian(ptr + (i * sizeof(int)), value);
            }
        }
    }
}
