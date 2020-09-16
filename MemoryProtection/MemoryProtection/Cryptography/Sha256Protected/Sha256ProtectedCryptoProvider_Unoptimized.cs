using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.Sha256Protected
{
    public class Sha256ProtectedCryptoProvider_Unoptimized : IProtectedHashFunction
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
            MarshalExtensions.Copy(pHash, 0, result.Handle, 0, digestLength);
            result.Protect();
            MarshalExtensions.ZeroMemory(pHash, digestLength);
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
            MarshalExtensions.ZeroMemory(hash, digestLength);
            Marshal.FreeHGlobal(hash);
            return result;
        }

        public string ComputeHash(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHash(protectedMemory);
        }

        private IntPtr Digest(ProtectedMemory protectedMemory)
        {
            // convert string msg into 512-bit blocks (array of 16 32-bit integers) [§5.2.1]
            int contentLength = protectedMemory.ContentLength;
            double length = (contentLength / 4) + 3;                        // length (in 32-bit integers) of content length + ‘1’ + appended length
            int blockCount = (int)Math.Ceiling(length / 16d);            // number of 16-integer (512-bit) blocks required to hold 'l' ints
            int allocatedSize = blockCount * 16 * sizeof(int);
            IntPtr messageBuffer = Marshal.AllocHGlobal(allocatedSize);
            MarshalExtensions.ZeroMemory(messageBuffer, allocatedSize);
            try
            {
                protectedMemory.Unprotect();
                MarshalExtensions.Copy(protectedMemory.Handle, 0, messageBuffer, 0, contentLength);
            }
            finally
            {
                protectedMemory.Protect();
            }
            // append padding
            Marshal.WriteByte(messageBuffer + contentLength, 0x80);
            IntPtr buffer = Marshal.AllocHGlobal(allocatedSize);
            MarshalExtensions.ZeroMemory(buffer, allocatedSize);
            for (int i = 0; i < blockCount; i++)
            {
                IntPtr rowPointer = messageBuffer + (i * 64);
                // encode 4 chars per integer (64 per block), big-endian encoding
                for (int j = 0; j < 16; j++)
                {
                    int value = MarshalExtensions.ReadInt32BigEndian(rowPointer + (j * sizeof(int)));
                    Marshal.WriteInt32(buffer + (sizeof(int) * ((i * 16) + j)), value);
                }
            }
            // zero-free message buffer
            MarshalExtensions.ZeroMemory(messageBuffer, allocatedSize);
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
                // prepare message schedule
                for (int j = 0; j < 16; j++)
                {
                    int value = Marshal.ReadInt32(buffer + (sizeof(int) * ((i * 16) + j)));
                    Marshal.WriteInt32(messageScheduleBuffer + (j * sizeof(int)), value);
                }
                for (int j = 16; j < 64; j++)
                {
                    uint value = sigma1((uint)Marshal.ReadInt32(messageScheduleBuffer + ((j - 2) * sizeof(int))))
                                 + (uint)Marshal.ReadInt32(messageScheduleBuffer + ((j - 7) * sizeof(int)))
                                 + sigma0((uint)Marshal.ReadInt32(messageScheduleBuffer + ((j - 15) * sizeof(int))))
                                 + (uint)Marshal.ReadInt32(messageScheduleBuffer + ((j - 16) * sizeof(int)));
                    Marshal.WriteInt32(messageScheduleBuffer + (j * sizeof(int)), (int)value);
                }
                // initialize working variables a, b, c, d, e, f, g, h with previous hash value
                uint a = (uint)Marshal.ReadInt32(pHash + (0 * sizeof(int)));
                uint b = (uint)Marshal.ReadInt32(pHash + (1 * sizeof(int)));
                uint c = (uint)Marshal.ReadInt32(pHash + (2 * sizeof(int)));
                uint d = (uint)Marshal.ReadInt32(pHash + (3 * sizeof(int)));
                uint e = (uint)Marshal.ReadInt32(pHash + (4 * sizeof(int)));
                uint f = (uint)Marshal.ReadInt32(pHash + (5 * sizeof(int)));
                uint g = (uint)Marshal.ReadInt32(pHash + (6 * sizeof(int)));
                uint h = (uint)Marshal.ReadInt32(pHash + (7 * sizeof(int)));
                // main loop
                for (int j = 0; j < 64; j++)
                {
                    uint t1 = h + sum1(e) + Ch(e, f, g) + K[j] + (uint)Marshal.ReadInt32(messageScheduleBuffer + (j * sizeof(int)));
                    uint t2 = sum0(a) + Maj(a, b, c);
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
                Marshal.WriteInt32(pHash + (0 * sizeof(int)), (int)((uint)Marshal.ReadInt32(pHash + (0 * sizeof(int))) + a));
                Marshal.WriteInt32(pHash + (1 * sizeof(int)), (int)((uint)Marshal.ReadInt32(pHash + (1 * sizeof(int))) + b));
                Marshal.WriteInt32(pHash + (2 * sizeof(int)), (int)((uint)Marshal.ReadInt32(pHash + (2 * sizeof(int))) + c));
                Marshal.WriteInt32(pHash + (3 * sizeof(int)), (int)((uint)Marshal.ReadInt32(pHash + (3 * sizeof(int))) + d));
                Marshal.WriteInt32(pHash + (4 * sizeof(int)), (int)((uint)Marshal.ReadInt32(pHash + (4 * sizeof(int))) + e));
                Marshal.WriteInt32(pHash + (5 * sizeof(int)), (int)((uint)Marshal.ReadInt32(pHash + (5 * sizeof(int))) + f));
                Marshal.WriteInt32(pHash + (6 * sizeof(int)), (int)((uint)Marshal.ReadInt32(pHash + (6 * sizeof(int))) + g));
                Marshal.WriteInt32(pHash + (7 * sizeof(int)), (int)((uint)Marshal.ReadInt32(pHash + (7 * sizeof(int))) + h));
            }
            MarshalExtensions.Int32LittleEndianArrayToBigEndian(pHash, digestLength);
            // zero-free used buffers
            MarshalExtensions.ZeroMemory(messageScheduleBuffer, msgSchedBufSize);
            Marshal.FreeHGlobal(messageScheduleBuffer);
            MarshalExtensions.ZeroMemory(buffer, allocatedSize);
            Marshal.FreeHGlobal(buffer);
            // return pointer to computed hash (needs to be freed by caller).
            return pHash;
        }

        private uint RotateRight(uint x, int places)
        {
            return (x >> places) | (x << (32 - places));
        }

        private uint sum0(uint x)
        {
            return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22);
        }

        private uint sum1(uint x)
        {
            return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25);
        }

        private uint sigma0(uint x)
        {
            return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
        }

        private uint sigma1(uint x)
        {
            return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
        }

        private uint Ch(uint x, uint y, uint z)
        {
            return (x & y) ^ (~x & z);
        }

        private uint Maj(uint x, uint y, uint z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
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
