using pmdbs2X.Security.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using System.Text.Json;

namespace pmdbs2X.Security.ProtectedCryptography.Aes256Protected
{
    // https://github.com/kokke/tiny-AES-c/blob/master/aes.c
    internal class AesState
    {
        private static readonly byte[] SBox = new byte[] {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

        private static readonly byte[] RSBox = new byte[] {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

        // The round constant word array, RoundConstants[i], contains the values given by
        // x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
        private static readonly byte[] RoundConstants = new byte[] {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

        private const int Nb = 4;
        private const int Nk = 8;
        private const int Nr = 14;

        private const int KeyLength = 32;
        private const int KeyExpSize = 240;
        private const int AesBlockLength = 16;

        private readonly ProtectedMemory protectedRoundKey;

        private readonly byte[] iv;

        internal AesState(ProtectedMemory key, byte[] iv)
        {
            protectedRoundKey = ProtectedMemory.Allocate(KeyExpSize);
            this.iv = new byte[16];
            Buffer.BlockCopy(iv, 0, this.iv, 0, 16);
            KeyExpansion(key);
        }

        // This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
        private unsafe void KeyExpansion(ProtectedMemory protectedKey)
        {
            IntPtr hBuffer = Marshal.AllocHGlobal(4);
            byte* buffer = (byte*)hBuffer;
            using ProtectedMemoryAccess roundKeyAccess = new ProtectedMemoryAccess(protectedRoundKey);
            uint* roundKey = (uint*)roundKeyAccess.Handle;
            using (ProtectedMemoryAccess keyAccess = new ProtectedMemoryAccess(protectedKey))
            {
                uint* key = (uint*)keyAccess.Handle;
                // The first round key is the key itself.
                for (int i = 0; i < Nk; i++)
                {
                    roundKey[i] = key[i];
                }
            }
            for (int i = Nk; i < Nb * (Nr + 1); i++)
            {
                *(uint*)buffer = roundKey[i - 1];
                if ((i & 0x7) == 0) // if (i % 8 == 0)
                {
                    RotateWord(buffer);
                    SubWord(buffer);
                    buffer[0] ^= RoundConstants[i / Nk];
                }
                if ((i & 0x7) == 0x4) // if (i % 8 == 4)
                {
                    SubWord(buffer);
                }
                roundKey[i] = roundKey[i - Nk] ^ buffer[0];
            }
            Marshal.FreeHGlobal(hBuffer);
        }

        internal unsafe void AesCbcDecryptBuffer(ProtectedMemory protectedBuffer)
        {
            IntPtr hIvBuffer = Marshal.AllocHGlobal(AesBlockLength);
            byte* ivBuffer = (byte*)hIvBuffer;
            using ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedBuffer);
            using ProtectedMemoryAccess roundKeyAccess = new ProtectedMemoryAccess(protectedRoundKey);
            byte* buffer = (byte*)access.Handle;
            byte* roundKey = (byte*)roundKeyAccess.Handle;
            State state = new State(buffer);
            fixed (byte* originalIv = iv)
            {
                byte* iv = originalIv;
                for (int i = 0; i < protectedBuffer.ContentLength; i += AesBlockLength)
                {
                    Unsafe.CopyBlock(ivBuffer, state.Buffer, AesBlockLength);
                    InverseCipher(state, roundKey);
                    XorWithIv(state.Buffer, iv);
                    Unsafe.CopyBlock(iv, ivBuffer, AesBlockLength);
                    state.Buffer += AesBlockLength;
                }
            }
            Marshal.FreeHGlobal(hIvBuffer);
        }

        internal unsafe void AesCbcDecryptBuffer(ref byte[] buffer)
        {
            IntPtr hIvBuffer = Marshal.AllocHGlobal(AesBlockLength);
            byte* ivBuffer = (byte*)hIvBuffer;
            using ProtectedMemoryAccess roundKeyAccess = new ProtectedMemoryAccess(protectedRoundKey);
            fixed (byte* pBuffer = buffer)
            {
                byte* roundKey = (byte*)roundKeyAccess.Handle;
                State state = new State(pBuffer);
                fixed (byte* originalIv = iv)
                {
                    byte* iv = originalIv;
                    for (int i = 0; i < buffer.Length; i += AesBlockLength)
                    {
                        Unsafe.CopyBlock(ivBuffer, state.Buffer, AesBlockLength);
                        InverseCipher(state, roundKey);
                        XorWithIv(state.Buffer, iv);
                        Unsafe.CopyBlock(iv, ivBuffer, AesBlockLength);
                        state.Buffer += AesBlockLength;
                    }
                }
            }
            Marshal.FreeHGlobal(hIvBuffer);
        }

        private unsafe void InverseCipher(State state, byte* roundKey)
        {
            int round;

            // Add the First round key to the state before starting the rounds.
            AddRoundKey(Nr, state, roundKey);

            // There will be Nr rounds.
            // The first Nr-1 rounds are identical.
            for (round = Nr - 1; round > 0; round--)
            {
                InverseShiftRows(state);
                InverseSubBytes(state);
                AddRoundKey(round, state, roundKey);
                InverseMixColumns(state);
            }
            // The last round without InverseMixColumns()
            InverseShiftRows(state);
            InverseSubBytes(state);
            AddRoundKey(round, state, roundKey);
        }

        private unsafe void InverseShiftRows(State state)
        {
            // Rotate first row 1 columns to right
            byte temp = state[3][1];
            state[3][1] = state[2][1];
            state[2][1] = state[1][1];
            state[1][1] = state[0][1];
            state[0][1] = temp;

            // Rotate second row 2 columns to right
            temp = state[0][2];
            state[0][2] = state[2][2];
            state[2][2] = temp;

            temp = state[1][2];
            state[1][2] = state[3][2];
            state[3][2] = temp;

            // Rotate third row 3 columns to right
            temp = state[0][3];
            state[0][3] = state[1][3];
            state[1][3] = state[2][3];
            state[2][3] = state[3][3];
            state[3][3] = temp;
        }

        // The SubBytes Function Substitutes the values in the
        // state matrix with values in an S-box.
        private unsafe void InverseSubBytes(State state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[j][i] = RSBox[state[j][i]];
                }
            }
        }

        // MixColumns function mixes the columns of the state matrix.
        // The method used to multiply may be difficult to understand for the inexperienced.
        // Please use the references to gain more information.
        private unsafe void InverseMixColumns(State state)
        {
            byte a, b, c, d;
            for (int i = 0; i < 4; i++)
            {
                a = state[i][0];
                b = state[i][1];
                c = state[i][2];
                d = state[i][3];

                state[i][0] = (byte)(Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09));
                state[i][1] = (byte)(Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d));
                state[i][2] = (byte)(Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b));
                state[i][3] = (byte)(Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e));
            }
        }

        // Multiply is used to multiply numbers in the field GF(2^8)
        private static unsafe byte Multiply(byte x, byte y)
        {
            return (byte)(((y & 1) * x) ^
                         (((y >> 1) & 1) * XTime(x)) ^
                         (((y >> 2) & 1) * XTime(XTime(x))) ^
                         (((y >> 3) & 1) * XTime(XTime(XTime(x)))));
        }

        internal unsafe void AesCbcEncryptBuffer(ProtectedMemory protectedBuffer)
        {
            fixed (byte* originalIv = iv)
            {
                byte* iv = originalIv;
                using ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedBuffer);
                using ProtectedMemoryAccess roundKeyAccess = new ProtectedMemoryAccess(protectedRoundKey);
                byte* buffer = (byte*)access.Handle;
                byte* roundKey = (byte*)roundKeyAccess.Handle;
                State state = new State(buffer);
                for (int i = 0; i < protectedBuffer.ContentLength; i += AesBlockLength)
                {
                    XorWithIv(state.Buffer, iv);
                    Cipher(state, roundKey);
                    iv = state.Buffer;
                    state.Buffer += AesBlockLength;
                }
                Marshal.Copy(new IntPtr(iv), this.iv, 0, this.iv.Length);
            }
        }

        internal unsafe void AesCbcEncryptBuffer(ref byte[] buffer)
        {
            fixed (byte* originalIv = iv)
            {
                byte* iv = originalIv;
                using ProtectedMemoryAccess roundKeyAccess = new ProtectedMemoryAccess(protectedRoundKey);
                fixed (byte* pBuffer = buffer)
                {
                    byte* roundKey = (byte*)roundKeyAccess.Handle;
                    State state = new State(pBuffer);
                    for (int i = 0; i < buffer.Length; i += AesBlockLength)
                    {
                        XorWithIv(state.Buffer, iv);
                        Cipher(state, roundKey);
                        iv = state.Buffer;
                        state.Buffer += AesBlockLength;
                    }
                    Marshal.Copy(new IntPtr(iv), this.iv, 0, this.iv.Length);
                }
            }
        }

        private unsafe void XorWithIv(byte* buffer, byte* iv)
        {
            for (int i = 0; i < AesBlockLength; i++)
            {
                buffer[i] ^= iv[i];
            }
        }

        // Cipher is the main function that encrypts the PlainText.
        private unsafe void Cipher(State state, byte* roundKey)
        {
            int round = 0;
            // Add the First round key to the state before starting the rounds.
            AddRoundKey(round, state, roundKey);

            // There will be Nr rounds.
            // The first Nr-1 rounds are identical.
            for (round = 1; round < Nr; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(round, state, roundKey);
            }
            // The last round without MixColumns()
            SubBytes(state);
            ShiftRows(state);
            // Add round key to last round
            AddRoundKey(Nr, state, roundKey);
        }

        // This function adds the round key to state.
        // The round key is added to the state by an XOR function.
        private unsafe void AddRoundKey(int round, State state, byte* roundKey)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i][j] ^= roundKey[(round * Nb * 4) + (i * Nb) + j];
                }
            }
        }

        // This function shifts the 4 bytes in a word to the left once.
        // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
        private unsafe void RotateWord(byte* buffer)
        {
            byte temp = buffer[0];
            buffer[0] = buffer[1];
            buffer[1] = buffer[2];
            buffer[2] = buffer[3];
            buffer[3] = temp;
        }

        // SubWord() is a function that takes a four-byte input word and
        // applies the S-box to each of the four bytes to produce an output word.
        private unsafe void SubWord(byte* buffer)
        {
            buffer[0] = SBox[buffer[0]];
            buffer[1] = SBox[buffer[1]];
            buffer[2] = SBox[buffer[2]];
            buffer[3] = SBox[buffer[3]];
        }

        // The SubBytes Function Substitutes the values in the
        // state matrix with values in an S-box.
        private unsafe void SubBytes(State state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[j][i] = SBox[state[j][i]];
                }
            }
        }

        // The ShiftRows() function shifts the rows in the state to the left.
        // Each row is shifted with different offset.
        // Offset = Row number. So the first row is not shifted.
        private unsafe void ShiftRows(State state)
        {
            // Rotate first row 1 columns to left
            byte temp = state[0][1];
            state[0][1] = state[1][1];
            state[1][1] = state[2][1];
            state[2][1] = state[3][1];
            state[3][1] = temp;

            // Rotate second row 2 columns to left
            temp = state[0][2];
            state[0][2] = state[2][2];
            state[2][2] = temp;

            temp = state[1][2];
            state[1][2] = state[3][2];
            state[3][2] = temp;

            // Rotate third row 3 columns to left
            temp = state[0][3];
            state[0][3] = state[3][3];
            state[3][3] = state[2][3];
            state[2][3] = state[1][3];
            state[1][3] = temp;
        }

        // MixColumns function mixes the columns of the state matrix
        private unsafe void MixColumns(State state)
        {
            byte Tmp, Tm, t;
            for (int i = 0; i < 4; i++)
            {
                t = state[i][0];
                Tmp = (byte)(state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3]);
                Tm = (byte)(state[i][0] ^ state[i][1]);

                Tm = XTime(Tm);
                state[i][0] ^= (byte)(Tm ^ Tmp);

                Tm = (byte)(state[i][1] ^ state[i][2]);
                Tm = XTime(Tm);
                state[i][1] ^= (byte)(Tm ^ Tmp);

                Tm = (byte)(state[i][2] ^ state[i][3]);
                Tm = XTime(Tm);
                state[i][2] ^= (byte)(Tm ^ Tmp);

                Tm = (byte)(state[i][3] ^ t);
                Tm = XTime(Tm);
                state[i][3] ^= (byte)(Tm ^ Tmp);
            }
        }

        private static byte XTime(byte x)
        {
            return (byte)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
        }

        private unsafe class State
        {
            internal byte* Buffer { get; set; }

            internal State(byte* buffer)
            {
                Buffer = buffer;
            }

            public byte* this[int index]
            {
                get { return Buffer + (index * 4); }
            }
        }
    }
}