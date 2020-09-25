using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.Blake2bProtected
{
    public class Blake2bProtectedCryptoProvider : ProtectedHashFunction
    {
        public override string ComputeHash(ProtectedMemory protectedMemory)
        {
            IntPtr hash = Digest(32, protectedMemory);
            byte[] resultBytes = new byte[32];
            Marshal.Copy(hash, resultBytes, 0, 32);
            string result = ByteArrayToString(resultBytes);
            MarshalExtensions.ZeroMemory(hash, 32);
            Marshal.FreeHGlobal(hash);
            return result;
        }

        public override string ComputeHash(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHash(protectedMemory);
        }

        public override ProtectedMemory ComputeHashProtected(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHashProtected(protectedMemory);
        }

        public override ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory)
        {
            IntPtr pHash = Digest(32, protectedMemory);
            ProtectedMemory result = ProtectedMemory.Allocate(32);
            using (ProtectedMemoryAccess access = new ProtectedMemoryAccess(result))
            {
                MarshalExtensions.Copy(pHash, 0, access.Handle, 0, 32);
            }
            MarshalExtensions.ZeroMemory(pHash, 32);
            Marshal.FreeHGlobal(pHash);
            return result;
        }

        private unsafe IntPtr Digest(int digestLength, ProtectedMemory protectedMemory)
        {
            Blake2bHashState blake2 = default;
            blake2.Init(digestLength);
            int length = protectedMemory.ContentLength;
            IntPtr hInput = Marshal.AllocHGlobal(length);
            using (ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedMemory))
            {
                MarshalExtensions.Copy(access.Handle, 0, hInput, 0, length);
            }
            byte* input = (byte*)hInput;
            blake2.Update(input, length);
            MarshalExtensions.ZeroMemory(hInput, length);
            Marshal.FreeHGlobal(hInput);
            IntPtr hash = blake2.Finish();
            blake2.Free();
            return hash;
        }
    }
}
