using MemoryProtection.MemoryProtection.Linux;
using MemoryProtection.MemoryProtection.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace MemoryProtection.MemoryProtection
{
    public abstract class ProtectedMemory : IDisposable
    {
        private protected IntPtr rawHandle;

        public IntPtr Handle { get; private protected set; }
        public int Size { get; private protected set; }

        public int ContentLength { get; private protected set; }

        public virtual void Dispose()
        {
            Free();
        }

        public virtual byte this[int i]
        {
            get => Read(i, 1)[0];
            set => Write(new byte[] { value }, i);
        }

        public abstract void Protect();

        public abstract void Unprotect();

        public virtual void Write(byte[] bytes, int offset)
        {
            try
            {
                Unprotect();
                if (IsOutOfBoundes(offset + bytes.Length))
                {
                    throw new IndexOutOfRangeException("Buffer overflow!");
                }
                Marshal.Copy(bytes, 0, Handle + offset, bytes.Length);
                if (offset + bytes.Length > ContentLength)
                {
                    ContentLength = offset + bytes.Length;
                }
            }
            finally
            {
                Protect();
            }
        }

        public abstract byte[] Read(int offset, int length);

        public virtual void CopyTo(int startIndex, ProtectedMemory destination, int destinationOffset, int length)
        {
            if (Size - startIndex > destination.Size - destinationOffset)
            {
                throw new ArgumentException("Destination cannot be smaller than source!");
            }
            try
            {
                destination.Unprotect();
                Unprotect();
                MarshalExtensions.Copy(Handle, startIndex, destination.Handle, destinationOffset, length);
            }
            finally
            {
                destination.Protect();
                Protect();
            }
        }

        public virtual byte Read(int offset)
        {
            try
            {
                Unprotect();
                return Marshal.ReadByte(Handle + offset);
            }
            finally
            {
                Protect();
            }
        }

        public virtual void Write(byte b, int offset)
        {
            try
            {
                Unprotect();
                if (IsOutOfBoundes(offset))
                {
                    throw new IndexOutOfRangeException("Buffer overflow!");
                }
                Marshal.WriteByte(Handle + offset, b);
                if (offset > ContentLength)
                {
                    ContentLength = offset;
                }
            }
            finally
            {
                Protect();
            }
        }

        private protected bool IsOutOfBoundes(int offset)
        {
            return (ulong)Handle + (uint)offset > (ulong)Handle + (uint)Size;
        }

        public abstract void Free();

        public static ProtectedMemory Allocate(int size)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Either use VirtualProtect() or CryptProtectMemory()

                // return new Win32ProtectedMemory(size);
                return new Win32EncryptedMemory(size);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
            {
                return new PosixProtectedMemory(size);
            }
            throw new NotImplementedException("This platform is currently not supported!");
        }

        public override bool Equals(object obj)
        {
            return Equals((ProtectedMemory)obj);
        }

        public virtual bool Equals(ProtectedMemory other)
        {
            Type thisType = GetType();
            Type otherType = other.GetType();
            if (thisType != otherType)
            {
                throw new ArgumentException("Cannot compare object of type " + thisType.FullName + " with type " + otherType.FullName + "!");
            }
            if (Size != other.Size)
            {
                return false;
            }
            try
            {
                Unprotect();
                other.Unprotect();
                for (int i = 0; i < Size; i++)
                {
                    if (Marshal.ReadByte(Handle + i) != Marshal.ReadByte(other.Handle + i))
                    {
                        return false;
                    }
                }
                return true;
            }
            finally
            {
                Protect();
                other.Protect();
            }
        }

        public static ProtectedMemory operator >> (ProtectedMemory memory, int offset)
        {
            if (offset < 0)
            {
                throw new ArgumentException("Shift offset cannot be negative!");
            }
            else if(offset == 0)
            {
                return memory;
            }
            int length = memory.ContentLength - offset;
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                memory.Unprotect();
                // We're shifting right, so we need a buffer because we'd override data we still need to copy.
                MarshalExtensions.CopyWithBuffer(memory.Handle, 0, memory.Handle, offset, length, buffer);
                MarshalExtensions.ZeroMemory(memory.Handle, offset);
                return memory;
            }
            finally
            {
                MarshalExtensions.ZeroMemory(buffer, length);
                memory.Protect();
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static ProtectedMemory operator <<(ProtectedMemory memory, int offset)
        {
            if (offset < 0)
            {
                throw new ArgumentException("Shift offset cannot be negative!");
            }
            else if (offset == 0)
            {
                return memory;
            }
            try
            {
                memory.Unprotect();
                MarshalExtensions.Copy(memory.Handle, offset, memory.Handle, 0, memory.ContentLength - offset);
                byte[] zeros = new byte[offset];
                Marshal.Copy(zeros, 0, memory.Handle + memory.ContentLength - offset, offset);
                return memory;
            }
            finally
            {
                memory.Protect();
            }
        }
    }
}
