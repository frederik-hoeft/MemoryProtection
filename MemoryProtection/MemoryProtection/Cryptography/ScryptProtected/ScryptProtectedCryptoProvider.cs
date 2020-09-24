using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.ScryptProtected
{
    public class ScryptProtectedCryptoProvider : IProtectedHashFunction
    {
        private unsafe IntPtr Digest(ProtectedMemory protectedMemory, uint desiredKeyLength)
        {
            ScryptHashFunction hashFunction = default;
            hashFunction.Init(65536, 8, 1, 32);
            byte[] b = Convert.FromBase64String("TB5ny6LI9KywU3+TD5FdrNSsxYV2T+3qyxRwMieu7zQ=");
            ProtectedMemory salt = ProtectedMemory.Allocate(b.Length);
            salt.Write(b, 0);
            IntPtr hHash = hashFunction.Digest(protectedMemory, salt);
            hashFunction.Free();
            byte[] hash = new byte[32];
            Marshal.Copy(hHash, hash, 0, 32);
            // Console.WriteLine(Convert.ToBase64String(hash));
            Marshal.FreeHGlobal(hHash);
            return IntPtr.Zero;
        }

        public string ComputeHash(ProtectedMemory protectedMemory)
        {
            _ = Digest(protectedMemory, 32);
            return null;
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
