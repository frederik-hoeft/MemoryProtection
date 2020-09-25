using MemoryProtection.MemoryProtection.Cryptography.Sha256Protected;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Mail;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.ScryptProtected
{
    internal class ScryptHashFunction : IDisposable
    {
        private static readonly byte[] zeros64 = new byte[64];
        private readonly byte[] blockSizeZeros;
        private readonly int n;
        private readonly int r;
        private readonly int p;
        private readonly int outLength;
        private readonly uint blockSize;
        /*
         *                 +------------------------------+
         *                 |                              |
         *        +--------+----------+                   |
         *        |        |          |                   |
         *        |        |          v                   v
         * B --> byte*   byte* .... <data> * 128 * r... <data> * 128 * r ...
         */
        private readonly IntPtr hB;          // Handle for B
        private readonly unsafe byte** B;    // 2d byte array!
        private readonly int allocatedSize;

        internal unsafe ScryptHashFunction(int costFactor, int blockSizeFactor, int parallelizationFactor, int desiredKeyLength)
        {
            if (desiredKeyLength < 1)
            {
                throw new ArgumentException(nameof(desiredKeyLength) + " must be larger than 0.");
            }
            n = costFactor;
            r = blockSizeFactor;
            p = parallelizationFactor;
            outLength = desiredKeyLength;
            blockSize = (uint)(128 * blockSizeFactor);
            blockSizeZeros = new byte[(int)blockSize];
            allocatedSize = p * (sizeof(byte*) + (int)blockSize);

            hB = Marshal.AllocHGlobal(allocatedSize);
            MarshalExtensions.ZeroMemory(hB, allocatedSize);
            B = (byte**)hB;
            for (int i = 0; i < p; i++)
            {
                long offset = (p * sizeof(byte*)) + (i * blockSize);
                B[i] = (byte*)B + offset;
            }
        }

        internal unsafe IntPtr Digest(ProtectedMemory password, byte[] salt)
        {
            if (outLength == 0)
            {
                throw new InvalidOperationException("Hash not initialized.");
            }
            fixed (byte* pSalt = salt)
            {
                Pbkdf2HmacSha256(password, pSalt, salt.Length, 1, (int)blockSize * p, B[0]);
            }
            int iBlockSize = (int)blockSize;
            int vLength = n * iBlockSize;
            IntPtr hV = Marshal.AllocHGlobal(vLength);
            IntPtr hBuffer = Marshal.AllocHGlobal(iBlockSize);
            IntPtr hTempBuffer = Marshal.AllocHGlobal(64);
            byte* v = (byte*)hV;
            byte* buffer = (byte*)hBuffer;
            byte* tempBuffer = (byte*)hTempBuffer;
            for (int i = 0; i < p; i++)
            {
                /* https://en.wikipedia.org/wiki/Scrypt
                Function ROMix(Block, Iterations)

                    Create Iterations copies of X
                    X ← Block
                    for i ← 0 to Iterations−1 do
                        Vi ← X
                        X ← BlockMix(X)

                    for i ← 0 to Iterations−1 do
                        j ← Integerify(X) mod Iterations
                        X ← BlockMix(X xor Vj)

                    return X
                */
                byte* source = B[i] + (((2 * r) - 1) * 64);
                for (int k = 0; k < n; k++)
                {
                    Unsafe.CopyBlock(v + (k * blockSize), B[i], blockSize);
                    Unsafe.CopyBlock(tempBuffer, source, 64u);
                    BlockMix(B[i], v + (k * blockSize), tempBuffer);
                }
                long j;
                int len;
                for (int k = 0; k < n; k++)
                {
                    uint* temp = (uint*)(B[i] + (((blockSize >> 6) - 1) * 64));
                    // C# uses little-endian integers by default!
                    j = (((long)temp[1] << 32) + temp[0]) & (n - 1);
                    len = iBlockSize;
                    byte* d = B[i];
                    byte* s = v + (j * blockSize);

                    while (len >= 8)
                    {
                        *(ulong*)d ^= *(ulong*)s;
                        d += 8;
                        s += 8;
                        len -= 8;
                    }
                    if (len >= 4)
                    {
                        *(uint*)d ^= *(uint*)s;
                        d += 4;
                        s += 4;
                        len -= 4;
                    }
                    if (len >= 2)
                    {
                        *(ushort*)d ^= *(ushort*)s;
                        d += 2;
                        s += 2;
                        len -= 2;
                    }
                    if (len >= 1)
                    {
                        *d ^= *s;
                    }
                    Unsafe.CopyBlock(buffer, B[i], blockSize);
                    Unsafe.CopyBlock(tempBuffer, source, 64u);
                    BlockMix(B[i], buffer, tempBuffer);
                }
            }
            Marshal.Copy(blockSizeZeros, 0, hBuffer, iBlockSize);
            Marshal.FreeHGlobal(hBuffer);
            Marshal.Copy(zeros64, 0, hTempBuffer, 64);
            Marshal.FreeHGlobal(hTempBuffer);
            MarshalExtensions.ZeroFree(hV, vLength);
            IntPtr hOutput = Marshal.AllocHGlobal(outLength);
            byte* output = (byte*)hOutput;
            Pbkdf2HmacSha256(password, B[0], (int)blockSize * p, 1, outLength, output);
            return hOutput;
        }

        private static unsafe void Pbkdf2HmacSha256(ProtectedMemory password, byte* salt, int saltLength, long c, int dkLen, byte* result)
        {
            if (c < 1)
            {
                throw new ArgumentException("The count " + nameof(c) + " cannot be less than 1!");
            }
            const int digestLength = 0x20;
            int blockCount = (int)Math.Ceiling((double)dkLen / digestLength);
            int saltBufferLength = saltLength + sizeof(int);
            IntPtr hSaltBuffer = Marshal.AllocHGlobal(saltBufferLength);
            byte* saltBuffer = (byte*)hSaltBuffer;
            Unsafe.CopyBlock(saltBuffer, salt, (uint)saltLength);

            for (int i = 1; i <= blockCount; i++)
            {
                MarshalExtensions.WriteInt32BigEndian(saltBuffer + saltLength, i);
                Sha256ProtectedCryptoProvider sha256 = new Sha256ProtectedCryptoProvider();
                (IntPtr hU, _) = sha256.ComputeHmacUnsafe(password, saltBuffer, saltBufferLength);
                Unsafe.CopyBlock(result + ((i - 1) * digestLength), (void*)hU, digestLength);
                MarshalExtensions.ZeroFree(hU, digestLength);

                for (long j = 1; j < c; j++)
                {
                    (IntPtr hUi, _) = sha256.ComputeHmacUnsafe(password, saltBuffer, digestLength);
                    byte* ui = (byte*)hUi;
                    for (int k = 0; k < digestLength; k++)
                    {
                        (result + ((i - 1) * digestLength))[k] ^= ui[k];
                    }
                    MarshalExtensions.ZeroFree(hUi, digestLength);
                }
            }
            MarshalExtensions.ZeroFree(hSaltBuffer, saltBufferLength);
        }

        /* https://en.wikipedia.org/wiki/Scrypt
         Function BlockMix(B):
            The block B is r 128-byte chunks (which is equivalent of 2r 64-byte chunks)
            r ← Length(B) / 128;

            Treat B as an array of 2r 64-byte chunks
            [B0...B2r-1] ← B

            X ← B2r−1
            for i ← 0 to 2r−1 do
                X ← Salsa20/8(X xor Bi)  //Salsa20/8 hashes from 64-bytes to 64-bytes
                Yi ← X

            return ← Y0∥Y2∥...∥Y2r−2 ∥ Y1∥Y3∥...∥Y2r−1
         */
        private unsafe void BlockMix(byte* block, byte* input, byte* tempBuffer)
        {
            uint* y = (uint*)tempBuffer;
            uint x0;
            uint x1;
            uint x2;
            uint x3;
            uint x4;
            uint x5;
            uint x6;
            uint x7;
            uint x8;
            uint x9;
            uint x10;
            uint x11;
            uint x12;
            uint x13;
            uint x14;
            uint x15;
            for (int i = 0; i < (2 * r); i += 2)
            {
                int len = 64;
                byte* d = tempBuffer;
                byte* s = input + (i * 64);
                while (len >= 8)
                {
                    *(ulong*)d ^= *(ulong*)s;
                    d += 8;
                    s += 8;
                    len -= 8;
                }
                if (len >= 4)
                {
                    *(uint*)d ^= *(uint*)s;
                    d += 4;
                    s += 4;
                    len -= 4;
                }
                if (len >= 2)
                {
                    *(ushort*)d ^= *(ushort*)s;
                    d += 2;
                    s += 2;
                    len -= 2;
                }
                if (len >= 1)
                {
                    *d ^= *s;
                }
                x0 = y[0];
                x1 = y[1];
                x2 = y[2];
                x3 = y[3];
                x4 = y[4];
                x5 = y[5];
                x6 = y[6];
                x7 = y[7];
                x8 = y[8];
                x9 = y[9];
                x10 = y[10];
                x11 = y[11];
                x12 = y[12];
                x13 = y[13];
                x14 = y[14];
                x15 = y[15];

                for (int j = 0; j < 4; j++)
                {
                    /* Operate on columns. */
                    x4 ^= (x0 + x12 << 7) | (x0 + x12 >> 25);
                    x8 ^= (x4 + x0 << 9) | (x4 + x0 >> 23);
                    x12 ^= (x8 + x4 << 13) | (x8 + x4 >> 19);
                    x0 ^= (x12 + x8 << 18) | (x12 + x8 >> 14);

                    x9 ^= (x5 + x1 << 7) | (x5 + x1 >> 25);
                    x13 ^= (x9 + x5 << 9) | (x9 + x5 >> 23);
                    x1 ^= (x13 + x9 << 13) | (x13 + x9 >> 19);
                    x5 ^= (x1 + x13 << 18) | (x1 + x13 >> 14);

                    x14 ^= (x10 + x6 << 7) | (x10 + x6 >> 25);
                    x2 ^= (x14 + x10 << 9) | (x14 + x10 >> 23);
                    x6 ^= (x2 + x14 << 13) | (x2 + x14 >> 19);
                    x10 ^= (x6 + x2 << 18) | (x6 + x2 >> 14);

                    x3 ^= (x15 + x11 << 7) | (x15 + x11 >> 25);
                    x7 ^= (x3 + x15 << 9) | (x3 + x15 >> 23);
                    x11 ^= (x7 + x3 << 13) | (x7 + x3 >> 19);
                    x15 ^= (x11 + x7 << 18) | (x11 + x7 >> 14);

                    /* Operate on rows. */
                    x1 ^= (x0 + x3 << 7) | (x0 + x3 >> 25);
                    x2 ^= (x1 + x0 << 9) | (x1 + x0 >> 23);
                    x3 ^= (x2 + x1 << 13) | (x2 + x1 >> 19);
                    x0 ^= (x3 + x2 << 18) | (x3 + x2 >> 14);

                    x6 ^= (x5 + x4 << 7) | (x5 + x4 >> 25);
                    x7 ^= (x6 + x5 << 9) | (x6 + x5 >> 23);
                    x4 ^= (x7 + x6 << 13) | (x7 + x6 >> 19);
                    x5 ^= (x4 + x7 << 18) | (x4 + x7 >> 14);

                    x11 ^= (x10 + x9 << 7) | (x10 + x9 >> 25);
                    x8 ^= (x11 + x10 << 9) | (x11 + x10 >> 23);
                    x9 ^= (x8 + x11 << 13) | (x8 + x11 >> 19);
                    x10 ^= (x9 + x8 << 18) | (x9 + x8 >> 14);

                    x12 ^= (x15 + x14 << 7) | (x15 + x14 >> 25);
                    x13 ^= (x12 + x15 << 9) | (x12 + x15 >> 23);
                    x14 ^= (x13 + x12 << 13) | (x13 + x12 >> 19);
                    x15 ^= (x14 + x13 << 18) | (x14 + x13 >> 14);
                }
                uint* result = (uint*)(block + (i * 32));
                result[0] = y[0] += x0;
                result[1] = y[1] += x1;
                result[2] = y[2] += x2;
                result[3] = y[3] += x3;
                result[4] = y[4] += x4;
                result[5] = y[5] += x5;
                result[6] = y[6] += x6;
                result[7] = y[7] += x7;
                result[8] = y[8] += x8;
                result[9] = y[9] += x9;
                result[10] = y[10] += x10;
                result[11] = y[11] += x11;
                result[12] = y[12] += x12;
                result[13] = y[13] += x13;
                result[14] = y[14] += x14;
                result[15] = y[15] += x15;
                len = 64;
                d = tempBuffer;
                s = input + (i * 64) + 64;

                while (len >= 8)
                {
                    *(ulong*)d ^= *(ulong*)s;
                    d += 8;
                    s += 8;
                    len -= 8;
                }
                if (len >= 4)
                {
                    *(uint*)d ^= *(uint*)s;
                    d += 4;
                    s += 4;
                    len -= 4;
                }
                if (len >= 2)
                {
                    *(ushort*)d ^= *(ushort*)s;
                    d += 2;
                    s += 2;
                    len -= 2;
                }
                if (len >= 1)
                {
                    *d ^= *s;
                }
                x0 = y[0];
                x1 = y[1];
                x2 = y[2];
                x3 = y[3];
                x4 = y[4];
                x5 = y[5];
                x6 = y[6];
                x7 = y[7];
                x8 = y[8];
                x9 = y[9];
                x10 = y[10];
                x11 = y[11];
                x12 = y[12];
                x13 = y[13];
                x14 = y[14];
                x15 = y[15];

                for (int j = 0; j < 4; j++)
                {
                    /* Operate on columns. */
                    x4 ^= (x0 + x12 << 7) | (x0 + x12 >> 25);
                    x8 ^= (x4 + x0 << 9) | (x4 + x0 >> 23);
                    x12 ^= (x8 + x4 << 13) | (x8 + x4 >> 19);
                    x0 ^= (x12 + x8 << 18) | (x12 + x8 >> 14);

                    x9 ^= (x5 + x1 << 7) | (x5 + x1 >> 25);
                    x13 ^= (x9 + x5 << 9) | (x9 + x5 >> 23);
                    x1 ^= (x13 + x9 << 13) | (x13 + x9 >> 19);
                    x5 ^= (x1 + x13 << 18) | (x1 + x13 >> 14);

                    x14 ^= (x10 + x6 << 7) | (x10 + x6 >> 25);
                    x2 ^= (x14 + x10 << 9) | (x14 + x10 >> 23);
                    x6 ^= (x2 + x14 << 13) | (x2 + x14 >> 19);
                    x10 ^= (x6 + x2 << 18) | (x6 + x2 >> 14);

                    x3 ^= (x15 + x11 << 7) | (x15 + x11 >> 25);
                    x7 ^= (x3 + x15 << 9) | (x3 + x15 >> 23);
                    x11 ^= (x7 + x3 << 13) | (x7 + x3 >> 19);
                    x15 ^= (x11 + x7 << 18) | (x11 + x7 >> 14);

                    /* Operate on rows. */
                    x1 ^= (x0 + x3 << 7) | (x0 + x3 >> 25);
                    x2 ^= (x1 + x0 << 9) | (x1 + x0 >> 23);
                    x3 ^= (x2 + x1 << 13) | (x2 + x1 >> 19);
                    x0 ^= (x3 + x2 << 18) | (x3 + x2 >> 14);

                    x6 ^= (x5 + x4 << 7) | (x5 + x4 >> 25);
                    x7 ^= (x6 + x5 << 9) | (x6 + x5 >> 23);
                    x4 ^= (x7 + x6 << 13) | (x7 + x6 >> 19);
                    x5 ^= (x4 + x7 << 18) | (x4 + x7 >> 14);

                    x11 ^= (x10 + x9 << 7) | (x10 + x9 >> 25);
                    x8 ^= (x11 + x10 << 9) | (x11 + x10 >> 23);
                    x9 ^= (x8 + x11 << 13) | (x8 + x11 >> 19);
                    x10 ^= (x9 + x8 << 18) | (x9 + x8 >> 14);

                    x12 ^= (x15 + x14 << 7) | (x15 + x14 >> 25);
                    x13 ^= (x12 + x15 << 9) | (x12 + x15 >> 23);
                    x14 ^= (x13 + x12 << 13) | (x13 + x12 >> 19);
                    x15 ^= (x14 + x13 << 18) | (x14 + x13 >> 14);
                }
                result += r << 4;
                result[0] = y[0] += x0;
                result[1] = y[1] += x1;
                result[2] = y[2] += x2;
                result[3] = y[3] += x3;
                result[4] = y[4] += x4;
                result[5] = y[5] += x5;
                result[6] = y[6] += x6;
                result[7] = y[7] += x7;
                result[8] = y[8] += x8;
                result[9] = y[9] += x9;
                result[10] = y[10] += x10;
                result[11] = y[11] += x11;
                result[12] = y[12] += x12;
                result[13] = y[13] += x13;
                result[14] = y[14] += x14;
                result[15] = y[15] += x15;
            }
        }

        public void Dispose()
        {
            MarshalExtensions.ZeroMemory(hB, allocatedSize);
            Marshal.FreeHGlobal(hB);
        }
    }
}
