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
            return hHash;
        }

        public string ComputeHash(ProtectedMemory protectedMemory)
        {
            IntPtr hash = Digest(protectedMemory, 32);
            byte[] resultBytes = new byte[32];
            Marshal.Copy(hash, resultBytes, 0, 32);
            string result = Convert.ToBase64String(resultBytes);
            byte[] zeros = new byte[32];
            Marshal.Copy(zeros, 0, hash, 32);
            Marshal.FreeHGlobal(hash);
            return result;
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
