﻿using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography.Blake2bProtected
{
    internal unsafe partial struct Blake2bHashState
    {
		internal const int WordSize = sizeof(ulong);
		internal const int BlockWords = 16;
		internal const int BlockBytes = BlockWords * WordSize;
		internal const int HashWords = 8;
		internal const int HashBytes = HashWords * WordSize;
		internal const int MaxKeyBytes = HashBytes;

		private IntPtr hHash;
		private IntPtr hBlock;

		private byte* block;
		private ulong* hash;
		private fixed ulong t[2];
		private fixed ulong f[2];
		private uint c;
        private uint outlen;

		private static ReadOnlySpan<byte> iv => new byte[] {
			0x08, 0xC9, 0xBC, 0xF3, 0x67, 0xE6, 0x09, 0x6A,
			0x3B, 0xA7, 0xCA, 0x84, 0x85, 0xAE, 0x67, 0xBB,
			0x2B, 0xF8, 0x94, 0xFE, 0x72, 0xF3, 0x6E, 0x3C,
			0xF1, 0x36, 0x1D, 0x5F, 0x3A, 0xF5, 0x4F, 0xA5,
			0xD1, 0x82, 0xE6, 0xAD, 0x7F, 0x52, 0x0E, 0x51,
			0x1F, 0x6C, 0x3E, 0x2B, 0x8C, 0x68, 0x05, 0x9B,
			0x6B, 0xBD, 0x41, 0xFB, 0xAB, 0xD9, 0x83, 0x1F,
			0x79, 0x21, 0x7E, 0x13, 0x19, 0xCD, 0xE0, 0x5B
		};

		internal void Init(int digestLength)
		{
			hHash = Marshal.AllocHGlobal(HashBytes);
			hash = (ulong*)hHash;

			hBlock = Marshal.AllocHGlobal(BlockBytes);
			block = (byte*)hBlock;

			if (digestLength == 0 || (uint)digestLength > HashBytes)
            {
                throw new ArgumentOutOfRangeException(nameof(digestLength), "Value must be between 1 and " + HashBytes);
            }

            outlen = (uint)digestLength;
			fixed (byte* pIv = iv)
            {
				Unsafe.CopyBlock(hash, pIv, HashBytes);
			}
			hash[0] ^= 0x01010000u ^ 0u ^ outlen;
		}

		private void Compress(byte* input, uint offs, uint cb)
		{
			uint inc = Math.Min(cb, BlockBytes);
			fixed (Blake2bHashState* s = &this)
			{
				ulong* sh = s->hash;
				byte* pin = input + offs;
				byte* end = pin + cb;

				do
				{
					t[0] += inc;
					if (t[0] < inc)
                    {
                        t[1]++;
                    }

                    ulong* m = (ulong*)pin;
					MixScalar(sh, m);

					pin += inc;
				} while (pin < end);
			}
		}

		internal void Update(byte* input, int length)
		{
			if (outlen == 0)
            {
                throw new InvalidOperationException("Hash not initialized.");
            }
            if (f[0] != 0)
            {
                throw new InvalidOperationException("Hash has already been finalized.");
            }

            uint consumed = 0;
			uint remaining = (uint)length;

			uint blockrem = BlockBytes - c;
			if ((c != 0) && (remaining > blockrem))
			{
				if (blockrem != 0)
                {
                    Unsafe.CopyBlockUnaligned(block + c, input, blockrem);
                }

                c = 0;
				Compress(block, 0, BlockBytes);
				consumed += blockrem;
				remaining -= blockrem;
			}

			if (remaining > BlockBytes)
			{
				uint cb = (remaining - 1) & ~((uint)BlockBytes - 1);
				Compress(input, consumed, cb);
				consumed += cb;
				remaining -= cb;
			}

			if (remaining != 0)
			{
				Unsafe.CopyBlockUnaligned(block + c, input + consumed, remaining);
				c += remaining;
			}
		}

		internal IntPtr Finish()
		{
			if (outlen == 0)
            {
                throw new InvalidOperationException("Hash not initialized.");
            }
            if (f[0] != 0)
            {
                throw new InvalidOperationException("Hash has already been finalized.");
            }
            if (c < BlockBytes)
            {
                Unsafe.InitBlockUnaligned(block + c, 0, BlockBytes - c);
            }
            f[0] = ~0ul;
			Compress(block, 0, c);
			IntPtr hDigest = Marshal.AllocHGlobal((int)outlen);

            Unsafe.CopyBlockUnaligned((void*)hDigest, hash, outlen);
			return hDigest;
		}

		internal void Free()
        {
			MarshalExtensions.ZeroMemory(hHash, HashBytes);
			MarshalExtensions.ZeroMemory(hBlock, BlockBytes);
			Marshal.FreeHGlobal(hHash);
			Marshal.FreeHGlobal(hBlock);
		}
	}
}
