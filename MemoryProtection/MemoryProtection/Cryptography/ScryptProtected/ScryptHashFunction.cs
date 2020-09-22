using MemoryProtection.MemoryProtection.Cryptography.Sha256Protected;
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

        private const int digestLength = 0x20;

        private unsafe void Pbkdf2HmacSha256(byte* passphrase, int passLength, byte* salt, int saltLength, int c, int dkLen, byte* result)
        {
            for (int i = 0; i < dkLen / digestLength; i++)
            {
                if (c < 1)
                {
                    throw new ArgumentException("The count " + nameof(c) + " cannot be less than 1!");
                }
                int messageLength = saltLength + sizeof(int);
                IntPtr hMessage = Marshal.AllocHGlobal(messageLength);
                byte* message = (byte*)hMessage;
                Unsafe.CopyBlock(message, salt, (uint)saltLength);
                MarshalExtensions.WriteInt32BigEndian(message + saltLength, i);
                Sha256ProtectedCryptoProvider sha256 = new Sha256ProtectedCryptoProvider();
                (IntPtr hU1, _) = sha256.ComputeHmacUnsafe(passphrase, passLength, message, messageLength);
                Unsafe.CopyBlock(result + (i * digestLength), (void*)hU1, digestLength);
                MarshalExtensions.ZeroFree(hMessage, messageLength);
                MarshalExtensions.ZeroFree(hU1, digestLength);
                if (c > 1)
                {
                    hMessage = Marshal.AllocHGlobal(digestLength);
                    message = (byte*)hMessage;
                    Unsafe.CopyBlock(message, result + (i * digestLength), digestLength);
                    for (int j = 2; j <= c; j++)
                    {
                        (IntPtr hUi, _) = sha256.ComputeHmacUnsafe(passphrase, passLength, message, digestLength);
                        byte* ui = (byte*)hUi;
                        for (int k = 0; k < digestLength; k++)
                        {
                            (result + (i * digestLength))[k] ^= ui[k];
                        }
                        Unsafe.CopyBlock(message, ui, digestLength);
                        MarshalExtensions.ZeroFree(hUi, digestLength);
                    }
                    MarshalExtensions.ZeroFree(hMessage, digestLength);
                }
            }
        }

        private unsafe void ROMix(byte* block, int iterations)
        {

        }
    }
}
