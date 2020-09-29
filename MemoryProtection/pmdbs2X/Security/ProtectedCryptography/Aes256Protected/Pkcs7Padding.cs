using pmdbs2X.Security.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X.Security.ProtectedCryptography.Aes256Protected
{
    internal static class Pkcs7Padding
    {
        internal static unsafe int Apply(ProtectedMemory protectedMemory, uint dataLength, byte modulus)
        {
            byte paddedBytes = (byte)(modulus - (dataLength & (modulus - 1)));
            if (dataLength + paddedBytes > protectedMemory.ContentLength)
            {
                throw new ArgumentException("Buffer is to small to apply padding!", nameof(protectedMemory));
            }
            using (ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedMemory))
            {
                byte* buffer = (byte*)access.Handle;
                for (int i = 0; i < paddedBytes; i++)
                {
                    buffer[dataLength + i] = paddedBytes;
                }
            }
            return paddedBytes;
        }

        internal static unsafe int Apply(byte[] buffer, uint dataLength, byte modulus)
        {
            byte paddedBytes = (byte)(modulus - (dataLength & (modulus - 1)));
            if (dataLength + paddedBytes > buffer.Length)
            {
                throw new ArgumentException("Buffer is to small to apply padding!", nameof(buffer));
            }
            for (int i = 0; i < paddedBytes; i++)
            {
                buffer[dataLength + i] = paddedBytes;
            }
            return paddedBytes;
        }


        internal static unsafe bool Validate(ProtectedMemory protectedMemory, uint dataLength, byte modulus)
        {
            byte expectedPaddingBytes = (byte)(modulus - (dataLength % modulus));
            if (dataLength + expectedPaddingBytes > protectedMemory.ContentLength)
            {
                return false;
            }
            using (ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedMemory))
            {
                byte* buffer = (byte*)access.Handle;
                for (int i = 0; i < expectedPaddingBytes; i++)
                {
                    if (buffer[dataLength + i] != expectedPaddingBytes)
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        internal static unsafe int GetContentLength(ProtectedMemory protectedMemory, byte modulus)
        {
            int bufferSize = protectedMemory.ContentLength;
            /* test for valid buffer size */
            if (((uint)bufferSize & (modulus - 1)) != 0 || bufferSize < modulus)
            {
                return 0;
            }
            byte paddingValue = protectedMemory[bufferSize - 1];
            /* test for valid padding value */
            if (paddingValue < 1 || paddingValue > modulus)
            {
                return 0;
            }
            /* buffer must be at least padding_value + 1 in size */
            if (bufferSize < paddingValue + 1)
            {
                return 0;
            }
            bufferSize--;
            using (ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedMemory))
            {
                byte* buffer = (byte*)access.Handle;
                for (int count = 1; count < paddingValue; count++)
                {
                    bufferSize--;
                    if (buffer[bufferSize] != paddingValue)
                    {
                        return 0;
                    }
                }
            }
            return bufferSize;
        }

        internal static int GetContentLength(byte[] buffer, byte modulus)
        {
            int bufferSize = buffer.Length;
            /* test for valid buffer size */
            if (((uint)bufferSize & (modulus - 1)) != 0 || bufferSize < modulus)
            {
                return 0;
            }
            byte paddingValue = buffer[^1];
            /* test for valid padding value */
            if (paddingValue < 1 || paddingValue > modulus)
            {
                return 0;
            }
            /* buffer must be at least padding_value + 1 in size */
            if (bufferSize < paddingValue + 1)
            {
                return 0;
            }
            bufferSize--;
            for (int count = 1; count < paddingValue; count++)
            {
                bufferSize--;
                if (buffer[bufferSize] != paddingValue)
                {
                    return 0;
                }
            }
            return bufferSize;
        }
    }
}
