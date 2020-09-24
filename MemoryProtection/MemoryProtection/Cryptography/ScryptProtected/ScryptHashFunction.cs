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
    internal struct ScryptHashFunction
    {
        private static readonly byte[] zeros64 = new byte[64];
        private byte[] blockSizeZeros;
        private int n;
        private int p;
        private int outLength;
        private uint blockSize;
        /*
         *                 +------------------------------+
         *                 |                              |
         *        +--------+----------+                   |
         *        |        |          |                   |
         *        |        |          v                   v
         * B --> byte*   byte* .... <data> * 128 * r... <data> * 128 * r ...
         */
        private IntPtr hB;          // Handle for B
        private unsafe byte** B;    // 2d byte array!

        private int allocatedSize;
        internal unsafe void Init(int costFactor, int blockSizeFactor, int parallelizationFactor, int desiredKeyLength)
        {
            if (desiredKeyLength < 1)
            {
                throw new ArgumentException(nameof(desiredKeyLength) + " must be larger than 0.");
            }
            n = costFactor;
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

        internal unsafe IntPtr Digest(ProtectedMemory password, ProtectedMemory salt)
        {
            if (outLength == 0)
            {
                throw new InvalidOperationException("Hash not initialized.");
            }
            using (ProtectedMemoryAccess passwordAccess = new ProtectedMemoryAccess(password))
            using (ProtectedMemoryAccess saltAccess = new ProtectedMemoryAccess(salt))
            {
                Pbkdf2HmacSha256((byte*)passwordAccess.Handle, password.ContentLength, (byte*)saltAccess.Handle, salt.ContentLength, 1, (int)blockSize * p, B[0]);
            }
            for (int i = 0; i < p; i++)
            {
                ROMix(B[i], n);
            }
            IntPtr hOutput = Marshal.AllocHGlobal(outLength);
            byte* output = (byte*)hOutput;
            using (ProtectedMemoryAccess passwordAccess = new ProtectedMemoryAccess(password))
            {
                Pbkdf2HmacSha256((byte*)passwordAccess.Handle, password.ContentLength, B[0], (int)blockSize * p, 1, outLength, output);
            }
            return hOutput;
        }

        internal unsafe void Free()
        {
            MarshalExtensions.ZeroMemory(hB, allocatedSize);
            Marshal.FreeHGlobal(hB);
        }

        public static unsafe void Pbkdf2HmacSha256(byte* passphrase, int passLength, byte* salt, int saltLength, long c, int dkLen, byte* result)
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
                (IntPtr hU, _) = sha256.ComputeHmacUnsafe(passphrase, passLength, saltBuffer, saltBufferLength);
                Unsafe.CopyBlock(result + ((i - 1) * digestLength), (void*)hU, digestLength);
                MarshalExtensions.ZeroFree(hU, digestLength);

                for (long j = 1 ; j < c; j++)
                {
                    (IntPtr hUi, _) = sha256.ComputeHmacUnsafe(passphrase, passLength, saltBuffer, digestLength);
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

        private unsafe void ROMix(byte* block, int iterations)
        {
            int vLength = iterations * (int)blockSize;
            IntPtr hV = Marshal.AllocHGlobal(vLength);
            byte* v = (byte*)hV;
            for (int i = 0; i < iterations; i++)
            {
                Unsafe.CopyBlock(v + (i * blockSize), block, blockSize);
                BlockMix(block);
            }
            for (int i = 0; i < iterations; i++)
            {
                long j = Integerify(block) & (iterations - 1);
                for (int k = 0; k < blockSize; k++)
                {
                    block[k] ^= v[(j * blockSize) + k];
                }
                BlockMix(block);
            }
            MarshalExtensions.ZeroFree(hV, vLength);
        }

        // RFC 7914 defines Integerify(X) as the result of interpreting the last 64 bytes of the block as a little-endian integer
        private unsafe long Integerify(byte* block)
        {
            uint* x = (uint*)(block + (((blockSize >> 6) - 1) * 64));
            // C# uses little-endian integers by default!
            return ((long)x[1] << 32) + x[0];
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
        private unsafe void BlockMix(byte* block)
        {
            uint r = blockSize / 128;
            IntPtr hBuffer = Marshal.AllocHGlobal((int)blockSize);
            byte* buffer = (byte*)hBuffer;
            Unsafe.CopyBlock(buffer, block, blockSize);
            IntPtr hX = Marshal.AllocHGlobal(64);
            byte* x = (byte*)hX;
            Unsafe.CopyBlock(x, buffer + (((2 * r) - 1) * 64), 64u);
            for (int i = 0; i < (2 * r); i += 2)
            {
                for (int j = 0; j < 64; j++)
                {
                    x[j] ^= (buffer + (i * 64))[j];
                }
                Salsa208(x);
                Unsafe.CopyBlock(block + (i * 32), x, 64u);

                for (int j = 0; j < 64; j++)
                {
                    x[j] ^= (buffer + (i * 64) + 64)[j];
                }
                Salsa208(x);
                Unsafe.CopyBlock(block + (i * 32) + (r * 64), x, 64u);
            }
            Marshal.Copy(zeros64, 0, hX, 64);
            Marshal.FreeHGlobal(hX);
            Marshal.Copy(blockSizeZeros, 0, hBuffer, (int)blockSize);
            Marshal.FreeHGlobal(hBuffer);
        }



        private unsafe void Salsa208(byte* buffer)
        {
            IntPtr hX = Marshal.AllocHGlobal(64);
            uint* x = (uint*)hX;
            Unsafe.CopyBlock(x, buffer, 64);
            // 4 * 2 = 8 rounds
            for (int i = 0; i < 4; i++)
            {
                // Odd round
                *(x + 4) ^= (*(x + 0) + *(x + 12) << 7) | (*(x + 0) + *(x + 12) >> (32 - 7));
                *(x + 8) ^= (*(x + 4) + *(x + 0) << 9) | (*(x + 4) + *(x + 0) >> (32 - 9));
                *(x + 12) ^= (*(x + 8) + *(x + 4) << 13) | (*(x + 8) + *(x + 4) >> (32 - 13));
                *(x + 0) ^= (*(x + 12) + *(x + 8) << 18) | (*(x + 12) + *(x + 8) >> (32 - 18)); // column 1
                *(x + 9) ^= (*(x + 5) + *(x + 1) << 7) | (*(x + 5) + *(x + 1) >> (32 - 7));
                *(x + 13) ^= (*(x + 9) + *(x + 5) << 9) | (*(x + 9) + *(x + 5) >> (32 - 9));
                *(x + 1) ^= (*(x + 13) + *(x + 9) << 13) | (*(x + 13) + *(x + 9) >> (32 - 13));
                *(x + 5) ^= (*(x + 1) + *(x + 13) << 18) | (*(x + 1) + *(x + 13) >> (32 - 18));    // column 2
                *(x + 14) ^= (*(x + 10) + *(x + 6) << 7) | (*(x + 10) + *(x + 6) >> (32 - 7));
                *(x + 2) ^= (*(x + 14) + *(x + 10) << 9) | (*(x + 14) + *(x + 10) >> (32 - 9));
                *(x + 6) ^= (*(x + 2) + *(x + 14) << 13) | (*(x + 2) + *(x + 14) >> (32 - 13));
                *(x + 10) ^= (*(x + 6) + *(x + 2) << 18) | (*(x + 6) + *(x + 2) >> (32 - 18));  // column 3
                *(x + 3) ^= (*(x + 15) + *(x + 11) << 7) | (*(x + 15) + *(x + 11) >> (32 - 7));
                *(x + 7) ^= (*(x + 3) + *(x + 15) << 9) | (*(x + 3) + *(x + 15) >> (32 - 9));
                *(x + 11) ^= (*(x + 7) + *(x + 3) << 13) | (*(x + 7) + *(x + 3) >> (32 - 13));
                *(x + 15) ^= (*(x + 11) + *(x + 7) << 18) | (*(x + 11) + *(x + 7) >> (32 - 18)); // column 4
                // Even round
                *(x + 1) ^= (*(x + 0) + *(x + 3) << 7) | (*(x + 0) + *(x + 3) >> (32 - 7));
                *(x + 2) ^= (*(x + 1) + *(x + 0) << 9) | (*(x + 1) + *(x + 0) >> (32 - 9));
                *(x + 3) ^= (*(x + 2) + *(x + 1) << 13) | (*(x + 2) + *(x + 1) >> (32 - 13));
                *(x + 0) ^= (*(x + 3) + *(x + 2) << 18) | (*(x + 3) + *(x + 2) >> (32 - 18));  // row 1
                *(x + 6) ^= (*(x + 5) + *(x + 4) << 7) | (*(x + 5) + *(x + 4) >> (32 - 7));
                *(x + 7) ^= (*(x + 6) + *(x + 5) << 9) | (*(x + 6) + *(x + 5) >> (32 - 9));
                *(x + 4) ^= (*(x + 7) + *(x + 6) << 13) | (*(x + 7) + *(x + 6) >> (32 - 13));
                *(x + 5) ^= (*(x + 4) + *(x + 7) << 18) | (*(x + 4) + *(x + 7) >> (32 - 18));  // row 2
                *(x + 11) ^= (*(x + 10) + *(x + 9) << 7) | (*(x + 10) + *(x + 9) >> (32 - 7));
                *(x + 8) ^= (*(x + 11) + *(x + 10) << 9) | (*(x + 11) + *(x + 10) >> (32 - 9));
                *(x + 9) ^= (*(x + 8) + *(x + 11) << 13) | (*(x + 8) + *(x + 11) >> (32 - 13));
                *(x + 10) ^= (*(x + 9) + *(x + 8) << 18) | (*(x + 9) + *(x + 8) >> (32 - 18));  // row 3
                *(x + 12) ^= (*(x + 15) + *(x + 14) << 7) | (*(x + 15) + *(x + 14) >> (32 - 7));
                *(x + 13) ^= (*(x + 12) + *(x + 15) << 9) | (*(x + 12) + *(x + 15) >> (32 - 9));
                *(x + 14) ^= (*(x + 13) + *(x + 12) << 13) | (*(x + 13) + *(x + 12) >> (32 - 13));
                *(x + 15) ^= (*(x + 14) + *(x + 13) << 18) | (*(x + 14) + *(x + 13) >> (32 - 18));	// row 4
            }
            for (int i = 0; i < 16; i++)
            {
                ((uint*)buffer)[i] += x[i];
            }
            Marshal.Copy(zeros64, 0, hX, 64);
            Marshal.FreeHGlobal(hX);
        }
    }
}
