using MemoryProtection.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.ProtectedString
{
    // This is a continuous region of ProtectedMemory.
    // During comparison the whole thing will be unprotected.
    public class ProtectedStringBlock : IProtectedString
    {
        private ProtectedMemory protectedMemory;
        public int Length { get; private set; } = 0;

        public ProtectedStringBlock()
        {
            protectedMemory = ProtectedMemory.Allocate(0);
        }

        public void Append(char c)
        {
            Rune rune = new Rune(c);
            byte[] bytes = new byte[rune.Utf8SequenceLength];
            rune.EncodeToUtf8(bytes);
            if (protectedMemory.ContentLength + rune.Utf8SequenceLength >= protectedMemory.Size)
            {
                ProtectedMemory newProtectedMemory = ProtectedMemory.Allocate(2 * protectedMemory.Size);
                protectedMemory.CopyTo(0, newProtectedMemory, 0, Length);
                protectedMemory.Free();
                protectedMemory = newProtectedMemory;
            }
            protectedMemory.Write(bytes, protectedMemory.ContentLength);
            Length++;
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

        public ProtectedMemory GetProtectedUtf8Bytes()
        {
            ProtectedMemory result = ProtectedMemory.Allocate(protectedMemory.ContentLength);
            protectedMemory.CopyTo(0, result, 0, protectedMemory.ContentLength);
            return result;
        }
    }
}
