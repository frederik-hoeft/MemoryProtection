using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.Blake2bProtected
{
    public class Blake2bProtectedCryptoProvider : IProtectedHashFunction
    {
        public string ComputeHash(ProtectedMemory protectedMemory)
        {
            IntPtr hash = Digest(32, protectedMemory);
            byte[] resultBytes = new byte[32];
            Marshal.Copy(hash, resultBytes, 0, 32);
            string result = ByteArrayToString(resultBytes);
            MarshalExtensions.ZeroMemory(hash, 32);
            Marshal.FreeHGlobal(hash);
            return result;
        }

        public string ComputeHash(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHash(protectedMemory);
        }

        public ProtectedMemory ComputeHashProtected(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHashProtected(protectedMemory);
        }

        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory)
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

        public static string ByteArrayToString(byte[] bytes)
        {
            StringBuilder stringBuilder = new StringBuilder(bytes.Length * 2);
            char[] hexAlphabet = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

            for (int i = 0; i < bytes.Length; i++)
            {
                stringBuilder.Append(hexAlphabet[bytes[i] >> 4]);
                stringBuilder.Append(hexAlphabet[bytes[i] & 0xF]);
            }

            return stringBuilder.ToString();
        }
    }
}
