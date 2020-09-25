using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography
{
    public abstract class ProtectedHashFunction : IProtectedHashFunction
    {
        private static RNGCryptoServiceProvider rngCryptoService;
        private protected RNGCryptoServiceProvider RngCryptoService => rngCryptoService ??= new RNGCryptoServiceProvider();

        public abstract string ComputeHash(ProtectedMemory protectedMemory);

        public abstract string ComputeHash(IProtectedString protectedString);

        public abstract ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory);

        public abstract ProtectedMemory ComputeHashProtected(IProtectedString protectedString);

        private protected string ByteArrayToString(byte[] bytes)
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

        private protected byte[] GetRandomBytes(int size)
        {
            byte[] bytes = new byte[size];
            RngCryptoService.GetBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// Checks if two strings are equal. Compares every char to prevent timing attacks.
        /// </summary>
        /// <param name="a">String to compare.</param>
        /// <param name="b">String to compare.</param>
        /// <returns>True if both strings are equal</returns>
        private protected bool SafeEquals(string a, string b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            uint diff = 0;

            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ (uint)b[i];
            }
            return diff == 0;
        }

        private protected bool SafeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            uint diff = 0;

            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ (uint)b[i];
            }
            return diff == 0;
        }
    }
}
