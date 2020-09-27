using MemoryProtection.MemoryProtection.Cryptography.Aes256Protected;
using MemoryProtection.MemoryProtection.Cryptography.Blake2bProtected;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography
{

    public class ProtectedAesProvider : ICryptoServiceOwner
    {
        public ProtectedAesProvider()
        {

        }

        private unsafe ProtectedMemory DeriveHmacKey(ProtectedMemory key)
        {
            using ProtectedMemory protectedBuffer = ProtectedMemory.Allocate(64);
            key.CopyTo(0, protectedBuffer, 0, 64);
            using (ProtectedMemoryAccess bufferAccess = new ProtectedMemoryAccess(protectedBuffer))
            {
                ulong* buffer = (ulong*)bufferAccess.Handle;
                for (int i = 0; i < 64 / sizeof(ulong); i++)
                {
                    buffer[i] ^= 0x5c;
                }
            }
            Blake2bProtectedCryptoProvider blake2b = new Blake2bProtectedCryptoProvider();
            return blake2b.ComputeHashProtected(protectedBuffer, 64);
        }

        private unsafe ProtectedMemory DeriveAesKey(ProtectedMemory key)
        {
            using ProtectedMemory protectedBuffer = ProtectedMemory.Allocate(64);
            key.CopyTo(0, protectedBuffer, 0, 64);
            using (ProtectedMemoryAccess bufferAccess = new ProtectedMemoryAccess(protectedBuffer))
            {
                ulong* buffer = (ulong*)bufferAccess.Handle;
                for (int i = 0; i < 64 / sizeof(ulong); i++)
                {
                    buffer[i] ^= 0x36;
                }
            }
            Blake2bProtectedCryptoProvider blake2b = new Blake2bProtectedCryptoProvider();
            return blake2b.ComputeHashProtected(protectedBuffer, 32);
        }

        private unsafe ProtectedMemory Decrypt(ProtectedMemory key, string message)
        {
            Blake2bProtectedCryptoProvider blake2b = new Blake2bProtectedCryptoProvider();
            using ProtectedMemory paddedKey = blake2b.ComputeHashProtected(key, 64);
            byte[] rawMessageBytes = Convert.FromBase64String(message);
            byte[] iv = rawMessageBytes[0..16];
            byte[] hmac = rawMessageBytes[^64..];
            byte[] messageBytes = rawMessageBytes[16..^64];
            using (ProtectedMemory hmacKey = DeriveHmacKey(paddedKey))
            {
                byte[] actualHmac = blake2b.CalculateHmac(hmacKey, rawMessageBytes[..^64]); // don't forget the IV
                byte isInvalid = 0x0;
                for (int i = 0; i < 64; i++)
                {
                    isInvalid |= (byte)(hmac[i] ^ actualHmac[i]);
                }
                if (isInvalid != 0x0)
                {
                    throw new SecurityException("Encountered invalid HMAC during decryption!");
                }
            }
            // TODO: Padding!
            ProtectedMemory result = ProtectedMemory.Allocate(messageBytes.Length);
            result.Write(messageBytes, 0);
            using (ProtectedMemory aesKey = DeriveAesKey(paddedKey))
            {
                AesState aesState = new AesState(aesKey, iv);
                aesState.AesCbcDecryptBuffer(result);
            }
            return result;
        }

        public string Encrypt(ProtectedMemory key, ProtectedMemory message)
        {
            Blake2bProtectedCryptoProvider blake2b = new Blake2bProtectedCryptoProvider();
            using ProtectedMemory paddedKey = blake2b.ComputeHashProtected(key, 64);
            byte[] iv = new byte[16];
            ICryptoServiceOwner.RngCryptoService.GetBytes(iv);
            using ProtectedMemory protectedBuffer = ProtectedMemory.Allocate(message.ContentLength);
            message.CopyTo(0, protectedBuffer, 0, message.ContentLength);
            using (ProtectedMemory aesKey = DeriveAesKey(paddedKey))
            {
                AesState aesState = new AesState(aesKey, iv);
                aesState.AesCbcDecryptBuffer(protectedBuffer);
            }
            byte[] aesResult = new byte[protectedBuffer.ContentLength + 16];
            Buffer.BlockCopy(iv, 0, aesResult, 0, 16);
            using (ProtectedMemoryAccess bufferAccess = new ProtectedMemoryAccess(protectedBuffer))
            {
                Marshal.Copy(bufferAccess.Handle, aesResult, 16, protectedBuffer.ContentLength);
            }
            byte[] hmac;
            using (ProtectedMemory hmacKey = DeriveHmacKey(paddedKey))
            {
                hmac = blake2b.CalculateHmac(hmacKey, aesResult);
            }
            byte[] result = new byte[aesResult.Length + hmac.Length];
            Buffer.BlockCopy(aesResult, 0, result, 0, aesResult.Length);
            Buffer.BlockCopy(hmac, 0, result, result.Length - hmac.Length, hmac.Length);
            return Convert.ToBase64String(result);
        }
    }
}
