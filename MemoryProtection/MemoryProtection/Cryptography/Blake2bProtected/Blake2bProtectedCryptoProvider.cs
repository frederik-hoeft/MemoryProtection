using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.Blake2bProtected
{
    public class Blake2bProtectedCryptoProvider : ProtectedHashFunction
    {
        public byte[] CalculateHmac(ProtectedMemory key, byte[] message)
        {
            byte[] mac = new byte[Blake2bHashState.HashSize];
            IntPtr hMac = DigestHmac(64, key, message);
            Marshal.Copy(hMac, mac, 0, mac.Length);
            Marshal.FreeHGlobal(hMac);
            return mac;
        }

        public override string ComputeHash(ProtectedMemory protectedMemory)
        {
            IntPtr hash = Digest(64, protectedMemory);
            byte[] resultBytes = new byte[64];
            Marshal.Copy(hash, resultBytes, 0, 64);
            string result = ByteArrayToString(resultBytes);
            MarshalExtensions.ZeroMemory(hash, 64);
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
            return ComputeHashProtected(protectedMemory, 64);
        }

        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory, int digestLength)
        {
            IntPtr pHash = Digest(digestLength, protectedMemory);
            ProtectedMemory result = ProtectedMemory.Allocate(digestLength);
            using (ProtectedMemoryAccess access = new ProtectedMemoryAccess(result))
            {
                MarshalExtensions.Copy(pHash, 0, access.Handle, 0, digestLength);
            }
            MarshalExtensions.ZeroMemory(pHash, digestLength);
            Marshal.FreeHGlobal(pHash);
            return result;
        }

        private unsafe IntPtr Digest(int digestLength, ProtectedMemory protectedMemory)
        {
            Blake2bHashState blake2 = default;
            blake2.Init(digestLength, null);
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

        private unsafe IntPtr DigestHmac(int digestLength, ProtectedMemory key, byte[] message)
        {
            Blake2bHashState blake2 = default;
            blake2.Init(digestLength, key);
            int length = message.Length;
            fixed(byte* input = message)
            {
                blake2.Update(input, length);
            }
            IntPtr hash = blake2.Finish();
            blake2.Free();
            return hash;
        }
    }
}
