using MemoryProtection.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography
{
    public interface IProtectedHashFunction
    {
        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory);

        public ProtectedMemory ComputeHashProtected(IProtectedString protectedString);

        public string ComputeHash(ProtectedMemory protectedMemory);

        public string ComputeHash(IProtectedString protectedString);
    }
}
