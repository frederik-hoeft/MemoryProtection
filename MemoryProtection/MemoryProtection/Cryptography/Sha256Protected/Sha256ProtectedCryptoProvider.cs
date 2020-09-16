using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.Sha256Protected
{
    public class Sha256ProtectedCryptoProvider : IProtectedHashFunction
    {
        private static readonly uint[] K = new uint[] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

        private static readonly uint[] H = new uint[] {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

        private const int digestLength = 0x20;
        private const int msgSchedBufSize = 64 * sizeof(int);

        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory)
        {
            IntPtr pHash = Digest(protectedMemory);
            ProtectedMemory result = ProtectedMemory.Allocate(digestLength);
            result.Unprotect();
            for (int i = 0; i < (digestLength / 2); i++)
            {
                short b = Marshal.ReadInt16(pHash + (2 * i));
                Marshal.WriteInt16(result.Handle + (2 * i), b);
            }
            result.Protect();
            byte[] zeros = new byte[digestLength];
            Marshal.Copy(zeros, 0, pHash, digestLength);
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
            IntPtr hash = Digest(protectedMemory);
            byte[] resultBytes = new byte[digestLength];
            Marshal.Copy(hash, resultBytes, 0, digestLength);
            string result = ByteArrayToString(resultBytes);
            byte[] zeros = new byte[digestLength];
            Marshal.Copy(zeros, 0, hash, digestLength);
            Marshal.FreeHGlobal(hash);
            return result;
        }

        public string ComputeHash(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHash(protectedMemory);
        }

        // This is what can only be called "optimized garbage" ... but it's 150% faster
        private IntPtr Digest(ProtectedMemory protectedMemory)
        {
            // convert string msg into 512-bit blocks (array of 16 32-bit integers) [§5.2.1]
            int contentLength = protectedMemory.ContentLength;
            double length = (contentLength / 4d) + 3;                        // length (in 32-bit integers) of content length + ‘1’ + appended length
            int blockCount = (int)Math.Ceiling(length / 16d);            // number of 16-integer (512-bit) blocks required to hold 'l' ints
            int allocatedSize = blockCount * 16 * sizeof(int);
            IntPtr messageBuffer = Marshal.AllocHGlobal(allocatedSize);
            byte[] allocatedSizeZeros = new byte[allocatedSize];
            Marshal.Copy(allocatedSizeZeros, 0, messageBuffer, allocatedSize);
            try
            {
                protectedMemory.Unprotect();
                if ((contentLength & 1) == 1)
                {
                    for (int i = 0; i < contentLength; i++)
                    {
                        byte b2 = Marshal.ReadByte(protectedMemory.Handle + i);
                        Marshal.WriteByte(messageBuffer + i, b2);
                    }
                }
                else
                {
                    for (int i = 0; i < (contentLength / 2); i++)
                    {
                        short b2 = Marshal.ReadInt16(protectedMemory.Handle + (2 * i));
                        Marshal.WriteInt16(messageBuffer + (2 * i), b2);
                    }
                }
            }
            finally
            {
                protectedMemory.Protect();
            }
            // append padding
            Marshal.WriteByte(messageBuffer + contentLength, 0x80);

            IntPtr buffer = Marshal.AllocHGlobal(allocatedSize);
            Marshal.Copy(allocatedSizeZeros, 0, buffer, allocatedSize);
            for (int i = 0; i < blockCount; i++)
            {
                IntPtr rowPointer = messageBuffer + (i * 64);
                int blockOffset = i * 16;
                // encode 4 chars per integer (64 per block), big-endian encoding
                for (int j = 0; j < 16; j++)
                {
                    IntPtr elementPointer = rowPointer + (j * sizeof(int));
                    Marshal.WriteInt32(buffer + (sizeof(int) * (blockOffset + j)), (Marshal.ReadByte(elementPointer) << 24) +
                                                                                   (Marshal.ReadByte(elementPointer + 1) << 16) +
                                                                                   (Marshal.ReadByte(elementPointer + 2) << 8) +
                                                                                    Marshal.ReadByte(elementPointer + 3));
                }
            }
            // zero-free message buffer

            Marshal.Copy(allocatedSizeZeros, 0, messageBuffer, allocatedSize);
            Marshal.FreeHGlobal(messageBuffer);
            // add length (in bits) into final pair of 32-bit integers (big-endian)
            long len = contentLength * 8;
            int lenHi = (int)(len >> 32);
            int lenLo = (int)len;
            Marshal.WriteInt32(buffer + allocatedSize - sizeof(long), lenHi);
            Marshal.WriteInt32(buffer + allocatedSize - sizeof(int), lenLo);

            // allocate message schedule
            IntPtr messageScheduleBuffer = Marshal.AllocHGlobal(msgSchedBufSize);

            // allocate memory for hash and copy constants.
            IntPtr pHash = Marshal.AllocHGlobal(digestLength);
            byte[] managedHash = new byte[H.Length * sizeof(uint)];
            Buffer.BlockCopy(H, 0, managedHash, 0, managedHash.Length);
            Marshal.Copy(managedHash, 0, pHash, managedHash.Length);

            // HASH COMPUTATION
            for (int i = 0; i < blockCount; i++)
            {
                int blockOffset = i * 16;
                // prepare message schedule
                for (int j = 0; j < 16; j++)
                {
                    Marshal.WriteInt32(messageScheduleBuffer + (j * sizeof(int)), Marshal.ReadInt32(buffer + (sizeof(int) * (blockOffset + j))));
                }
                for (int j = 16; j < 64; j++)
                {
                    uint sigma1In = (uint)Marshal.ReadInt32(messageScheduleBuffer + ((j - 2) * sizeof(int)));
                    uint sigma0In = (uint)Marshal.ReadInt32(messageScheduleBuffer + ((j - 15) * sizeof(int)));
                    Marshal.WriteInt32(messageScheduleBuffer + (j * sizeof(int)), (int)(
                        (((sigma1In >> 17) | (sigma1In << 15)) ^ ((sigma1In >> 19) | (sigma1In << 13)) ^ (sigma1In >> 10))
                        + (uint)Marshal.ReadInt32(messageScheduleBuffer + ((j - 7) * sizeof(int)))
                        + (((sigma0In >> 7) | (sigma0In << 25)) ^ ((sigma0In >> 18) | (sigma0In << 14)) ^ (sigma0In >> 3))
                        + (uint)Marshal.ReadInt32(messageScheduleBuffer + ((j - 16) * sizeof(int)))));
                }
                // initialize working variables a, b, c, d, e, f, g, h with previous hash value
                uint a = (uint)Marshal.ReadInt32(pHash);
                uint b = (uint)Marshal.ReadInt32(pHash + 0x4);
                uint c = (uint)Marshal.ReadInt32(pHash + 0x8);
                uint d = (uint)Marshal.ReadInt32(pHash + 0xC);
                uint e = (uint)Marshal.ReadInt32(pHash + 0x10);
                uint f = (uint)Marshal.ReadInt32(pHash + 0x14);
                uint g = (uint)Marshal.ReadInt32(pHash + 0x18);
                uint h = (uint)Marshal.ReadInt32(pHash + 0x1C);
                // main loop
                for (int j = 0; j < 64; j++)
                {
                    uint t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + K[j] + (uint)Marshal.ReadInt32(messageScheduleBuffer + (j * 4));
                    uint t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c));
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }
                // compute the new intermediate hash value
                Marshal.WriteInt32(pHash, (int)((uint)Marshal.ReadInt32(pHash) + a));
                Marshal.WriteInt32(pHash + 0x4, (int)((uint)Marshal.ReadInt32(pHash + 0x4) + b));
                Marshal.WriteInt32(pHash + 0x8, (int)((uint)Marshal.ReadInt32(pHash + 0x8) + c));
                Marshal.WriteInt32(pHash + 0xC, (int)((uint)Marshal.ReadInt32(pHash + 0xC) + d));
                Marshal.WriteInt32(pHash + 0x10, (int)((uint)Marshal.ReadInt32(pHash + 0x10) + e));
                Marshal.WriteInt32(pHash + 0x14, (int)((uint)Marshal.ReadInt32(pHash + 0x14) + f));
                Marshal.WriteInt32(pHash + 0x18, (int)((uint)Marshal.ReadInt32(pHash + 0x18) + g));
                Marshal.WriteInt32(pHash + 0x1C, (int)((uint)Marshal.ReadInt32(pHash + 0x1C) + h));
            }
            for (int j = 0; j < digestLength / sizeof(int); j++)
            {
                int value = Marshal.ReadInt32(pHash + (j * sizeof(int)));
                byte[] bytes = new byte[4];
                bytes[0] = (byte)(value >> 24);
                bytes[1] = (byte)(value >> 16);
                bytes[2] = (byte)(value >> 8);
                bytes[3] = (byte)value;
                Marshal.Copy(bytes, 0, pHash + (j * sizeof(int)), 4);
            }
            // zero-free used buffers
            Marshal.Copy(new byte[msgSchedBufSize], 0, messageScheduleBuffer, msgSchedBufSize);
            Marshal.FreeHGlobal(messageScheduleBuffer);
            Marshal.Copy(allocatedSizeZeros, 0, buffer, allocatedSize);
            Marshal.FreeHGlobal(buffer);
            // return pointer to computed hash (needs to be freed by caller).
            return pHash;
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
