using MemoryProtection.SelfProtection.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.SelfProtection.MemoryProtection.ProtectedString
{
    // This is a continuous region of ProtectedMemory.
    // During comparison the whole thing will be unprotected.
    public class ProtectedStringBlock : IProtectedString
    {
        private ProtectedMemory protectedMemory;
        public int Length { get; private set; } = 0;

        public ProtectedStringBlock()
        {
            protectedMemory = ProtectedMemory.Allocate(64);
        }

        public void Append(char c)
        {
            byte[] bytes = new byte[2];
            bytes[0] = (byte)(c >> 8);
            bytes[1] = (byte)c;
            if (Length + 2 >= protectedMemory.Size)
            {
                ProtectedMemory newProtectedMemory = ProtectedMemory.Allocate(2 * protectedMemory.Size);
                protectedMemory.CopyTo(0, newProtectedMemory, 0, Length);
                protectedMemory.Free();
                protectedMemory = newProtectedMemory;
            }
            protectedMemory.Write(bytes, Length);
            Length += 2;
        }

        public bool Equals(ProtectedStringBlock other)
        {
            if (Length != other.Length)
            {
                return false;
            }
            try
            {
                protectedMemory.Unprotect();
                other.protectedMemory.Unprotect();
                byte lastByte = 0;
                for (int i = 0; i < protectedMemory.Size; i++)
                {
                    byte thisByte = Marshal.ReadByte(protectedMemory.Handle + i);
                    byte otherByte = Marshal.ReadByte(other.protectedMemory.Handle + i);
                    if (thisByte != otherByte)
                    {
                        return false;
                    }
                    if (thisByte == 0 && lastByte == 0)
                    {
                        // null terminator reached
                        return true;
                    }
                    lastByte = thisByte;
                }
                return true;
            }
            finally
            {
                protectedMemory.Protect();
                other.protectedMemory.Protect();
            }
        }

        public void Dispose()
        {
            protectedMemory.Free();
        }

        public bool Equals(IProtectedString other)
        {
            if (GetType() != other.GetType())
            {
                return false;
            }
            return Equals((ProtectedStringBlock)other);
        }
    }
}
