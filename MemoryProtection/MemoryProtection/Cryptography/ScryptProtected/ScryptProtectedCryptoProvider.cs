using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.ScryptProtected
{
    public class ScryptProtectedCryptoProvider : IProtectedHashFunction
    {
        private readonly uint costFactor;
        private readonly uint blockSizeFactor;
        private readonly uint parellizationFactor;

        private unsafe IntPtr Digest(ProtectedMemory protectedMemory, uint desiredKeyLength)
        {
            return IntPtr.Zero;
        }

        public string ComputeHash(ProtectedMemory protectedMemory)
        {
            throw new NotImplementedException();
        }

        public string ComputeHash(IProtectedString protectedString)
        {
            throw new NotImplementedException();
        }

        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory)
        {
            throw new NotImplementedException();
        }

        public ProtectedMemory ComputeHashProtected(IProtectedString protectedString)
        {
            throw new NotImplementedException();
        }
    }
}
