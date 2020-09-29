using pmdbs2X.Security.MemoryProtection;
using pmdbs2X.Security.ProtectedCryptography;
using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X.Security.ProtectedCryptography.Sha3Protected
{
    // TODO: ...
    public class Sha3ProtectedCryptoProvider : IProtectedHashFunction
    {
        private readonly int keccakR;
        public Sha3ProtectedCryptoProvider(Sha3BitLength bitLength)
        {
            keccakR = (int)bitLength;
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

        private IntPtr Digest(ProtectedMemory protectedMemory)
        {
            return IntPtr.Zero;
        }
    }

    public enum Sha3BitLength
    {
        Sha3_512 = 576,
        Sha3_384 = 832,
        Sha3_256 = 1088,
        Sha3_224 = 1152,
    }
}
