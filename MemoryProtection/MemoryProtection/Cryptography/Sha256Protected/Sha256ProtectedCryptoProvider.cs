﻿using System;
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

        // This is what can only be called "optimized garbage" ... but it's more than twice as fast.
        private unsafe IntPtr Digest(ProtectedMemory protectedMemory)
        {
            // convert string msg into 512-bit blocks (array of 16 32-bit integers) [§5.2.1]
            int contentLength = protectedMemory.ContentLength;
            double length = (contentLength / 4d) + 3;                   // length (in 32-bit integers) of content length + ‘1’ + appended length
            int blockCount = (int)Math.Ceiling(length / 16d);           // number of 16-integer (512-bit) blocks required to hold 'l' ints
            int allocatedSize = blockCount * 16 * sizeof(int);
            IntPtr hMessageBuffer = Marshal.AllocHGlobal(allocatedSize);
            byte[] allocatedSizeZeros = new byte[allocatedSize];
            Marshal.Copy(allocatedSizeZeros, 0, hMessageBuffer, allocatedSize);
            byte* messageBuffer = (byte*)hMessageBuffer;
            try
            {
                protectedMemory.Unprotect();
                if ((contentLength & 1) == 1)
                {
                    byte* pProtectedMemory = (byte*)protectedMemory.Handle;
                    for (int i = 0; i < contentLength; i++)
                    {
                        messageBuffer[i] = pProtectedMemory[i];
                    }
                }
                else
                {
                    short* pProtectedMemory = (short*)protectedMemory.Handle;
                    short* pMessageBuffer = (short*)hMessageBuffer;
                    for (int i = 0; i < (contentLength / 2); i++)
                    {
                        pMessageBuffer[i] = pProtectedMemory[i];
                    }
                }
            }
            finally
            {
                protectedMemory.Protect();
            }
            // append padding
            messageBuffer[contentLength] = 0x80;

            IntPtr hBuffer = Marshal.AllocHGlobal(allocatedSize);
            int* buffer = (int*)hBuffer;
            int bufferLength = allocatedSize / sizeof(int);
            Marshal.Copy(allocatedSizeZeros, 0, hBuffer, allocatedSize);
            for (int i = 0; i < blockCount; i++)
            {
                byte* pRow = messageBuffer + (i * 64);
                int blockOffset = i * 16;
                // encode 4 chars per integer (64 per block), big-endian encoding
                for (int j = 0; j < 16; j++)
                {
                    byte* pElement = pRow + (j * sizeof(int));
                    buffer[blockOffset + j] = (pElement[0] << 24) + (pElement[1] << 16) + (pElement[2] << 8) + pElement[3];
                }
            }
            // zero-free message buffer
            Marshal.Copy(allocatedSizeZeros, 0, hMessageBuffer, allocatedSize);
            Marshal.FreeHGlobal(hMessageBuffer);
            // add length (in bits) into final pair of 32-bit integers (big-endian)
            long len = contentLength * 8;
            buffer[bufferLength - 2] = (int)(len >> 32);
            buffer[bufferLength - 1] = (int)len;

            // allocate message schedule
            IntPtr hMessageScheduleBuffer = Marshal.AllocHGlobal(msgSchedBufSize);
            int* messageScheduleBuffer = (int*)hMessageScheduleBuffer;

            // allocate memory for hash and copy constants.
            IntPtr hHash = Marshal.AllocHGlobal(digestLength);
            uint* hash = (uint*)hHash;
            const int hashLength = digestLength / sizeof(int);
            byte[] managedHash = new byte[H.Length * sizeof(uint)];
            Buffer.BlockCopy(H, 0, managedHash, 0, managedHash.Length);
            Marshal.Copy(managedHash, 0, hHash, managedHash.Length);

            // HASH COMPUTATION
            for (int i = 0; i < blockCount; i++)
            {
                int blockOffset = i * 16;
                // prepare message schedule
                for (int j = 0; j < 16; j++)
                {
                    messageScheduleBuffer[j] = buffer[blockOffset + j];
                }
                for (int j = 16; j < 64; j++)
                {
                    uint sigma1In = (uint)messageScheduleBuffer[j - 2];
                    uint sigma0In = (uint)messageScheduleBuffer[j - 15];
                    messageScheduleBuffer[j] = (int)(
                        (((sigma1In >> 17) | (sigma1In << 15)) ^ ((sigma1In >> 19) | (sigma1In << 13)) ^ (sigma1In >> 10))
                        + (uint)messageScheduleBuffer[j - 7]
                        + (((sigma0In >> 7) | (sigma0In << 25)) ^ ((sigma0In >> 18) | (sigma0In << 14)) ^ (sigma0In >> 3))
                        + (uint)messageScheduleBuffer[j - 16]);
                }
                // initialize working variables a, b, c, d, e, f, g, h with previous hash value
                uint a = hash[0];
                uint b = hash[1];
                uint c = hash[2];
                uint d = hash[3];
                uint e = hash[4];
                uint f = hash[5];
                uint g = hash[6];
                uint h = hash[7];
                // main loop
                for (int j = 0; j < 64; j++)
                {
                    uint t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + K[j] + (uint)messageScheduleBuffer[j];
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
                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
                hash[4] += e;
                hash[5] += f;
                hash[6] += g;
                hash[7] += h;
            }
            for (int j = 0; j < hashLength; j++)
            {
                int value = (int)hash[j];
                byte[] bytes = new byte[4];
                bytes[0] = (byte)(value >> 24);
                bytes[1] = (byte)(value >> 16);
                bytes[2] = (byte)(value >> 8);
                bytes[3] = (byte)value;
                Marshal.Copy(bytes, 0, hHash + (j * sizeof(int)), 4);
            }
            // zero-free used buffers
            Marshal.Copy(new byte[msgSchedBufSize], 0, hMessageScheduleBuffer, msgSchedBufSize);
            Marshal.FreeHGlobal(hMessageScheduleBuffer);
            Marshal.Copy(allocatedSizeZeros, 0, hBuffer, allocatedSize);
            Marshal.FreeHGlobal(hBuffer);
            // return pointer to computed hash (needs to be freed by caller).
            return hHash;
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