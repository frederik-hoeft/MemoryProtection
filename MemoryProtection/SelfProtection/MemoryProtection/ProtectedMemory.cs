using MemoryProtection.SelfProtection.MemoryProtection.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.SelfProtection.MemoryProtection
{
    public abstract class ProtectedMemory : IDisposable
    {
        private protected IntPtr rawHandle;

        public IntPtr Handle { get; private protected set; }
        public int Size { get; private protected set; }

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

        public abstract void Write(byte[] bytes, int offset);

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

        public abstract void Free();

        public static ProtectedMemory Allocate(int size)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Either use VirtualProtect() or CryptProtectMemory()

                // return new Win32ProtectedMemory(size);
                return new Win32EncryptedMemory(size);
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
    }
}
