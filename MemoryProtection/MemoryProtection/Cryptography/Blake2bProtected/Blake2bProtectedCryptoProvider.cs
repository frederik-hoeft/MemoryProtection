using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.Blake2bProtected
{
    public class Blake2bProtectedCryptoProvider : IProtectedHashFunction
    {
        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory)
        {
            IntPtr pHash = Digest(32, protectedMemory);
            ProtectedMemory result = ProtectedMemory.Allocate(32);
            result.Unprotect();
            MarshalExtensions.Copy(pHash, 0, result.Handle, 0, 32);
            result.Protect();
            MarshalExtensions.ZeroMemory(pHash, 32);
            Marshal.FreeHGlobal(pHash);
            return result;
        }

        public ProtectedMemory ComputeHashProtected(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHashProtected(protectedMemory);
        }

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

        private unsafe IntPtr Digest(int digestLength, ProtectedMemory protectedMemory)
        {
            Blake2bHashState hashState = default;
            hashState.Init(digestLength);
            int length = protectedMemory.ContentLength;
            IntPtr hInput = Marshal.AllocHGlobal(length);
            protectedMemory.Unprotect();
            MarshalExtensions.Copy(protectedMemory.Handle, 0, hInput, 0, length);
            protectedMemory.Protect();
            byte* input = (byte*)hInput;
            hashState.Update(input, length);
            MarshalExtensions.ZeroMemory(hInput, length);
            Marshal.FreeHGlobal(hInput);
            IntPtr hash = hashState.Finish();
            hashState.Free();
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
