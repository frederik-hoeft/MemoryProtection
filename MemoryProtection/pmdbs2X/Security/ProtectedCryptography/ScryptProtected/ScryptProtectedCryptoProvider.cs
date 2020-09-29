using pmdbs2X.Security.MemoryProtection;
using pmdbs2X.Security.ProtectedCryptography;
using pmdbs2X.Security.Unmanaged;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace pmdbs2X.Security.ProtectedCryptography.ScryptProtected
{
    public class ScryptProtectedCryptoProvider : ProtectedHashFunction
    {
        private unsafe IntPtr Digest(ProtectedMemory protectedMemory, byte[] salt, int n = 65536, int r = 8, int p = 1, int desiredKeyLength = 128)
        {
            using ScryptHashFunction hashFunction = new ScryptHashFunction(n, r, p, desiredKeyLength);
            return hashFunction.Digest(protectedMemory, salt);
        }

        public string ComputeHash(ProtectedMemory protectedMemory, byte[] salt, int n, int r, int p, int desiredKeyLength)
        {
            byte[] resultBytes = new byte[desiredKeyLength];
            IntPtr hash = Digest(protectedMemory, salt, n, r, p, desiredKeyLength);
            Marshal.Copy(hash, resultBytes, 0, desiredKeyLength);
            MarshalExtensions.ZeroFree(hash, desiredKeyLength);
            StringBuilder stringBuilder = new StringBuilder(desiredKeyLength + salt.Length + 20);
            stringBuilder.Append("$s2$");
            stringBuilder.Append(n.ToString()).Append('$');
            stringBuilder.Append(r.ToString()).Append('$');
            stringBuilder.Append(p.ToString()).Append('$');
            stringBuilder.Append(Convert.ToBase64String(salt)).Append('$');
            stringBuilder.Append(Convert.ToBase64String(resultBytes));
            return stringBuilder.ToString();
        }

        public string ComputeHash(ProtectedMemory protectedMemory, int n, int r, int p, int desiredKeyLength, int saltLength)
        {
            byte[] salt = GetRandomBytes(saltLength);
            return ComputeHash(protectedMemory, salt, n, r, p, desiredKeyLength);
        }

        public override string ComputeHash(ProtectedMemory protectedMemory)
        {
            return ComputeHash(protectedMemory, 65536, 8, 1, 128, 512);
        }

        public override string ComputeHash(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHash(protectedMemory);
        }

        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory, int n, int r, int p, int desiredKeyLength, byte[] salt)
        {
            IntPtr hash = Digest(protectedMemory, salt, n, r, p, desiredKeyLength);
            ProtectedMemory protectedResult = ProtectedMemory.Allocate(desiredKeyLength);
            using (ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedResult))
            {
                MarshalExtensions.Copy(hash, 0, access.Handle, 0, desiredKeyLength);
            }
            MarshalExtensions.ZeroFree(hash, desiredKeyLength);
            return protectedResult;
        }

        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory, int n, int r, int p, int desiredKeyLength, int saltLength)
        {
            byte[] salt = GetRandomBytes(saltLength);
            return ComputeHashProtected(protectedMemory, n, r, p, desiredKeyLength, salt);
        }

        public override ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory)
        {
            return ComputeHashProtected(protectedMemory, 65536, 8, 1, 128, 512);
        }

        public override ProtectedMemory ComputeHashProtected(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHashProtected(protectedMemory);
        }

        public bool Compare(ProtectedMemory protectedMemory, string hash)
        {
            ExtractHeader(hash, out int n, out int r, out int p, out byte[] salt, out byte[] expectedHash);
            using ProtectedMemory protectedResult = ComputeHashProtected(protectedMemory, n, r, p, expectedHash.Length, salt);
            byte[] result = new byte[expectedHash.Length];
            using (ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedResult))
            {
                Marshal.Copy(access.Handle, result, 0, result.Length);
            }
            return SafeEquals(result, expectedHash);
        }

        private void ExtractHeader(string hashedPassword, out int n, out int r, out int p, out byte[] salt, out byte[] hashedBytes)
        {
            if (!IsValid(hashedPassword))
            {
                throw new ArgumentException("Invalid hashed password", nameof(hashedPassword));
            }

            string[] parts = hashedPassword.Split('$');
            n = Convert.ToInt32(parts[2]);
            r = Convert.ToInt32(parts[3]);
            p = Convert.ToInt32(parts[4]);
            salt = Convert.FromBase64String(parts[5]);
            hashedBytes = Convert.FromBase64String(parts[6]);
        }

        /// <summary>
        /// Checks if the given hash is a valid scrypt hash
        /// </summary>
        public bool IsValid(string hashedPassword)
        {
            if (string.IsNullOrEmpty(hashedPassword))
            {
                return false;
            }

            string[] parts = hashedPassword.Split('$');

            if (parts.Length < 2 || parts[1].Length != 2)
            {
                return false;
            }

            int version = parts[1][1] - '0';

            if (version != 2)
            {
                return false;
            }
            if (parts.Length != 7)
            {
                return false;
            }
            return true;
        }
    }
}
