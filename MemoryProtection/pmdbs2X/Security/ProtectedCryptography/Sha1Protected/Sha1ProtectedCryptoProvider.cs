using pmdbs2X.Security.MemoryProtection;
using pmdbs2X.Security.ProtectedCryptography;
using System;
using System.Collections.Generic;
using System.Text;

namespace MemoryProtection.pmdbs2X.Security.ProtectedCryptography.Sha1Protected
{
    public class Sha1ProtectedCryptoProvider : ProtectedHashFunction
    {
        public override string ComputeHash(ProtectedMemory protectedMemory)
        {
            throw new NotImplementedException();
        }

        public override string ComputeHash(IProtectedString protectedString)
        {
            throw new NotImplementedException();
        }

        public override ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory)
        {
            throw new NotImplementedException();
        }

        public override ProtectedMemory ComputeHashProtected(IProtectedString protectedString)
        {
            throw new NotImplementedException();
        }
    }
}
