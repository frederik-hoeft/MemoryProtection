using pmdbs2X.Security.ProtectedCryptography.Sha3Protected;
using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;

namespace pmdbs2X.Security.MemoryProtection.ProtectedString
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

        public unsafe bool Equals(ProtectedStringBlock other)
        {
            if (Length != other.Length)
            {
                return false;
            }
            using ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedMemory);
            using ProtectedMemoryAccess otherAccess = new ProtectedMemoryAccess(other.protectedMemory);
            byte* memory = (byte*)access.Handle;
            byte* otherMemory = (byte*)otherAccess.Handle;
            byte lastByte = 0;
            for (int i = 0; i < protectedMemory.Size; i++)
            {
                if (memory[i] != otherMemory[i])
                {
                    return false;
                }
                if (memory[i] == 0 && lastByte == 0)
                {
                    // null terminator reached
                    return true;
                }
                lastByte = memory[i];
            }
            return true;
        }

        public void Dispose()
        {
            protectedMemory.Dispose();
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
