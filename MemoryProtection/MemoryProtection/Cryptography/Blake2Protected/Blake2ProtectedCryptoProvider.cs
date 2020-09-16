using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.Blake2Protected
{
    public class Blake2ProtectedCryptoProvider : IProtectedHashFunction
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct State
        {
            public IntPtr h, s, t;
            public const int hLen = 8 * sizeof(uint);
            public const int sLen = 4 * sizeof(uint);
            public const int tLen = 2 * sizeof(uint);
            public int buflen, nullt;
            public IntPtr buffer;
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

        private unsafe IntPtr Digest(ProtectedMemory protectedMemory)
        {
            IntPtr hState = Marshal.AllocHGlobal(sizeof(State));
            State* pState = (State*)hState;
            // TODO ...

            ZeroFree(pState);
            return IntPtr.Zero;
        }

        private unsafe void Initialize(State* pState)
        {
            pState->h = Marshal.AllocHGlobal(State.hLen);
            MarshalExtensions.Copy(iv, 0, pState->h, iv.Length);
            pState->s = Marshal.AllocHGlobal(State.sLen);
            MarshalExtensions.ZeroMemory(pState->s, State.sLen);
            pState->t = Marshal.AllocHGlobal(State.tLen);
            MarshalExtensions.ZeroMemory(pState->t, State.tLen);
        }

        private unsafe void ZeroFree(State* pState)
        {
            MarshalExtensions.ZeroMemory(pState->h, State.hLen);
            Marshal.FreeHGlobal(pState->h);
            MarshalExtensions.ZeroMemory(pState->s, State.sLen);
            Marshal.FreeHGlobal(pState->s);
            MarshalExtensions.ZeroMemory(pState->t, State.tLen);
            Marshal.FreeHGlobal(pState->t);
            Marshal.FreeHGlobal((IntPtr)pState);
        }

        public string ComputeHash(ProtectedMemory protectedMemory)
        {
            throw new NotImplementedException();
        }

        public string ComputeHash(IProtectedString protectedString)
        {
            throw new NotImplementedException();
        }

        public ProtectedMemory ComputeHashProtected(ProtectedMemory protectedMemory)
        {
            throw new NotImplementedException();
        }

        public ProtectedMemory ComputeHashProtected(IProtectedString protectedString)
        {
            throw new NotImplementedException();
        }
    }
    public enum Blake2BitLength
    {
        Blase2_224,
        Blake2_256
    }
}
