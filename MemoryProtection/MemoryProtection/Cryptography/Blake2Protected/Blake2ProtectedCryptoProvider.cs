using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.Blake2Protected
{
    public class Blake2ProtectedCryptoProvider : IProtectedHashFunction
    {
        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct State
        {
            public IntPtr hh, hs, ht;
            public uint* h, s, t;
            public const int hLen = 8 * sizeof(uint);
            public const int sLen = 4 * sizeof(uint);
            public const int tLen = 2 * sizeof(uint);
            public uint bufferLength, nullt;
            public IntPtr hBuffer;
            public uint* buffer;
        }

        private static readonly byte[,] sigma = new byte[,] {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
            {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
            {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
            { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
            { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
            { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
            {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
            {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
            { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
            {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
            {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
            { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8}};

        private static readonly uint[] cst = new uint[] {
            0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
            0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
            0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
            0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917};

        private static readonly byte[] padding = new byte[] {
            0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0   ,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

        private readonly uint[] iv;

        public Blake2ProtectedCryptoProvider(Blake2BitLength bitLength)
        {
            iv = bitLength switch
            {
                Blake2BitLength.Blake2_256 => new uint[]
                {
                    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
                },
                Blake2BitLength.Blase2_224 => new uint[]
                {
                    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
                    0xFFC00B31, 0x68581511, 0x64F98FA7, 0x64F98FA7
                },
                _ => throw new ArgumentException("Invalid Blake2BitLength!")
            };
        }

        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory)
        {
            IntPtr pHash = Digest(protectedMemory);
            ProtectedMemory result = ProtectedMemory.Allocate(32);
            result.Unprotect();
            MarshalExtensions.Copy(pHash, 0, result.Handle, 0, 32);
            result.Protect();
            MarshalExtensions.ZeroMemory(pHash, 32);
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
            byte[] resultBytes = new byte[32];
            Marshal.Copy(hash, resultBytes, 0, 32);
            string result = ByteArrayToString(resultBytes);
            MarshalExtensions.ZeroMemory(hash, 32);
            Marshal.FreeHGlobal(hash);
            return result;
        }

        public string ComputeHash(IProtectedString protectedString)
        {
            using ProtectedMemory protectedMemory = protectedString.GetProtectedUtf8Bytes();
            return ComputeHash(protectedMemory);
        }

        private unsafe IntPtr Digest(ProtectedMemory protectedMemory)
        {
            IntPtr hState = Marshal.AllocHGlobal(sizeof(State));
            State* pState = (State*)hState;
            Initialize(pState);
            try
            {
                protectedMemory.Unprotect();
                Update(pState, protectedMemory.Handle, (ulong)protectedMemory.ContentLength * 8ul);
            }
            finally
            {
                protectedMemory.Protect();
            }

            IntPtr hDigest = Marshal.AllocHGlobal(32);

            Final(pState, (byte*)hDigest);
            ZeroFree(pState);
            return hDigest;
        }

        private unsafe void Initialize(State* pState)
        {
            pState->hh = Marshal.AllocHGlobal(State.hLen);
            pState->h = (uint*)pState->hh;
            MarshalExtensions.Copy(iv, 0, pState->h, iv.Length);
            pState->hs = Marshal.AllocHGlobal(State.sLen);
            pState->s = (uint*)pState->hs;
            MarshalExtensions.ZeroMemory(pState->hs, State.sLen);
            pState->ht = Marshal.AllocHGlobal(State.tLen);
            pState->t = (uint*)pState->ht;
            MarshalExtensions.ZeroMemory(pState->ht, State.tLen);
            pState->hBuffer = Marshal.AllocHGlobal(64);
            pState->buffer = (uint*)pState->hBuffer;
            pState->bufferLength = 0;
            pState->nullt = 0;
        }

        private unsafe void Update(State* pState, IntPtr hData, ulong dataBitLength)
        {
            int left = (int)(pState->bufferLength / 8);
            int fill = 64 - left;
            if (left != 0 && (((dataBitLength / 8) & 0x3F) >= (uint)fill))
            {
                MarshalExtensions.Copy(hData, 0, pState->hBuffer, left, fill); // TODO: Check offset
                pState->t[0] += 512;
                if (pState->t[0] == 0)
                {
                    pState->t[1]++;
                }
                Compress(pState, (byte*)pState->buffer);
                hData += fill;
                dataBitLength -= (uint)(fill * 8);
                left = 0;
            }
            while (dataBitLength >= 512)
            {
                pState->t[0] += 512;
                if (pState->t[0] == 0)
                {
                    pState->t[1]++;
                }
                Compress(pState, (byte*)hData);
                hData += 64;
                dataBitLength -= 512;
            }
            if (dataBitLength > 0)
            {
                MarshalExtensions.Copy(hData, 0, pState->hBuffer, left, (int)(dataBitLength / 8));
                pState->bufferLength = (uint)((ulong)(left * 8) + dataBitLength);
            }
            else
            {
                pState->bufferLength = 0;
            }
        }

        private unsafe uint ByteToUInt32(byte* b)
        {
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private unsafe void UInt32ToBytes(byte* b, uint u)
        {
            b[0] = (byte)(u >> 24);
            b[1] = (byte)(u >> 16);
            b[2] = (byte)(u >> 8);
            b[3] = (byte)u;
        }

        private uint ROT(uint x, int n)
        {
            return (x << (32 - n)) | (x >> n);
        }

        private unsafe void G(uint* v, uint* m, uint a, uint b, uint c, uint d, uint e, uint i)
        {
            v[a] += (m[sigma[i, e]] ^ cst[sigma[i, e + 1]]) + v[b];
	        v[d] = ROT(v[d] ^ v[a], 16);
	        v[c] += v[d];
	        v[b] = ROT(v[b] ^ v[c], 12);
	        v[a] += (m[sigma[i, e + 1]] ^ cst[sigma[i, e]]) + v[b];
	        v[d] = ROT(v[d] ^ v[a], 8);
	        v[c] += v[d];
	        v[b] = ROT(v[b] ^ v[c], 7);
        }

        private unsafe void Compress(State* pState, byte* block)
        {
            IntPtr hv = Marshal.AllocHGlobal(16 * sizeof(uint));
            IntPtr hm = Marshal.AllocHGlobal(16 * sizeof(uint));

            uint* v = (uint*)hv;
            uint* m = (uint*)hm;

            for (int i = 0; i < 16; i++)
            {
                m[i] = ByteToUInt32(block + (i * sizeof(uint)));
            }
            for (int i = 0; i < 8; i++)
            {
                v[i] = pState->h[i];
            }
            v[8] = pState->s[0] ^ 0x243F6A88;
            v[9] = pState->s[1] ^ 0x85A308D3;
            v[10] = pState->s[2] ^ 0x13198A2E;
            v[11] = pState->s[3] ^ 0x03707344;
            v[12] = 0xA4093822;
            v[13] = 0x299F31D0;
            v[14] = 0x082EFA98;
            v[15] = 0xEC4E6C89;

            if (pState->nullt == 0)
            {
                v[12] ^= pState->t[0];
                v[13] ^= pState->t[0];
                v[14] ^= pState->t[1];
                v[15] ^= pState->t[1];
            }

            for (uint i = 0; i < 14; i++)
            {
                G(v, m, 0, 4, 8, 12, 0, i);
                G(v, m, 1, 5, 9, 13, 2, i);
                G(v, m, 2, 6, 10, 14, 4, i);
                G(v, m, 3, 7, 11, 15, 6, i);
                G(v, m, 3, 4, 9, 14, 14, i);
                G(v, m, 2, 7, 8, 13, 12, i);
                G(v, m, 0, 5, 10, 15, 8, i);
                G(v, m, 1, 6, 11, 12, 10, i);
            }

            for (int i = 0; i < 16; i++)
            {
                pState->h[i % 8] ^= v[i];
            }
            for (int i = 0; i < 8; i++)
            {
                pState->h[i] ^= pState->s[i % 4];
            }

            MarshalExtensions.ZeroMemory(hv, 16 * sizeof(uint));
            MarshalExtensions.ZeroMemory(hm, 16 * sizeof(uint));
            Marshal.FreeHGlobal(hv);
            Marshal.FreeHGlobal(hm);
        }

        private unsafe void Final(State* pState, byte* digest)
        {
            FinalH(pState, digest, 0x81, 0x01);
        }

        private unsafe void FinalH(State* pState, byte* digest, byte pa, byte pb)
        {
            IntPtr hMessageLength = Marshal.AllocHGlobal(8);
            byte* messageLength = (byte*)hMessageLength;
            uint lo = pState->t[0] + pState->bufferLength;
            uint hi = pState->t[1];
            if (lo < pState->bufferLength)
            {
                hi++;
            }
            UInt32ToBytes(messageLength, hi);
            UInt32ToBytes(messageLength + sizeof(uint), lo);

            if (pState->bufferLength == 440) // one padding byte
            {
                pState->t[0] -= 8;
                Update(pState, (IntPtr)(&pa), 8);
            }
            else
            {
                if (pState->bufferLength < 440) // enough space to fill the block
                {
                    if (pState->bufferLength == 0)
                    {
                        pState->nullt = 1;
                    }
                    pState->t[0] -= 440 - pState->bufferLength;
                    fixed (byte* pad = padding)
                    {
                        Update(pState, (IntPtr)pad, 440 - pState->bufferLength);
                    }
                }
                else //need 2 compressions
                {
                    pState->t[0] -= 512 - pState->bufferLength;
                    fixed (byte* pad = padding)
                    {
                        Update(pState, (IntPtr)pad, 512 - pState->bufferLength);
                        pState->t[0] -= 440;
                        Update(pState, (IntPtr)(pad + 1), 440);
                        pState->nullt = 1;
                    }
                }
                Update(pState, (IntPtr)(&pb), 8);
                pState->t[0] -= 8;
            }

            pState->t[0] -= 64;
            Update(pState, hMessageLength, 64);
            MarshalExtensions.ZeroMemory(hMessageLength, 8);
            Marshal.FreeHGlobal(hMessageLength);

            UInt32ToBytes(digest + 0, pState->h[0]);
            UInt32ToBytes(digest + 4, pState->h[1]);
            UInt32ToBytes(digest + 8, pState->h[2]);
            UInt32ToBytes(digest + 12, pState->h[3]);
            UInt32ToBytes(digest + 16, pState->h[4]);
            UInt32ToBytes(digest + 20, pState->h[5]);
            UInt32ToBytes(digest + 24, pState->h[6]);
            UInt32ToBytes(digest + 28, pState->h[7]);
        }

        private unsafe void ZeroFree(State* pState)
        {
            MarshalExtensions.ZeroMemory(pState->hh, State.hLen);
            Marshal.FreeHGlobal(pState->hh);
            MarshalExtensions.ZeroMemory(pState->hs, State.sLen);
            Marshal.FreeHGlobal(pState->hs);
            MarshalExtensions.ZeroMemory(pState->ht, State.tLen);
            Marshal.FreeHGlobal(pState->ht);
            Marshal.FreeHGlobal((IntPtr)pState);
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
    public enum Blake2BitLength
    {
        Blase2_224,
        Blake2_256
    }
}
