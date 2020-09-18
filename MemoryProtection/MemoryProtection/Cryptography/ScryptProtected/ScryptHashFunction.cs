using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.ScryptProtected
{
    internal struct ScryptHashFunction
    {
        private int n;
        private int r;
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
            r = blockSizeFactor;
            p = parallelizationFactor;
            outLength = desiredKeyLength;
            blockSize = (uint)(128 * blockSizeFactor);
            allocatedSize = p * (sizeof(byte*) + (int)blockSize);

            hB = Marshal.AllocHGlobal(allocatedSize);
            B = (byte**)hB;
            for (int i = 0; i < p; i++)
            {
                B[i] = (byte*)B + (p * sizeof(byte*)) + (i * blockSize);
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
                Pbkdf2Sha256((byte*)passwordAccess.Handle, password.ContentLength, (byte*)saltAccess.Handle, salt.ContentLength, 1, (int)blockSize * p, B[0]);
            }
            for (int i = 0; i < p; i++)
            {
                ROMix(B[i], n);
            }
            IntPtr hOutput = Marshal.AllocHGlobal(outLength);
            byte* output = (byte*)hOutput;
            using (ProtectedMemoryAccess passwordAccess = new ProtectedMemoryAccess(password))
            {
                Pbkdf2Sha256((byte*)passwordAccess.Handle, password.ContentLength, B[0], (int)blockSize * p, 1, outLength, output);
            }
            return hOutput;
        }

        internal unsafe void Free()
        {
            MarshalExtensions.ZeroMemory(hB, allocatedSize);
            Marshal.FreeHGlobal(hB);
        }

        private unsafe void Pbkdf2Sha256(byte* passphrase, int passLength, byte* salt, int saltLength, int c, int dkLen, byte* output)
        {

        }

        private unsafe void ROMix(byte* block, int iterations)
        {

        }
    }
}
