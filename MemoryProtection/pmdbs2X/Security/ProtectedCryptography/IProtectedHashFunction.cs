using pmdbs2X.Security.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X.Security.ProtectedCryptography
{
    public interface IProtectedHashFunction
    {
        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory);

        public ProtectedMemory ComputeHashProtected(IProtectedString protectedString);

        public string ComputeHash(ProtectedMemory protectedMemory);

        public string ComputeHash(IProtectedString protectedString);
    }
}
