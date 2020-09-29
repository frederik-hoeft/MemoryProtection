using pmdbs2X.Security.MemoryProtection;
using pmdbs2X.Security.ProtectedCryptography;
using pmdbs2X.Security.ProtectedCryptography.Aes256Protected;
using pmdbs2X.Security.ProtectedCryptography.Blake2bProtected;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace pmdbs2X.Security.ProtectedCryptography.Cryptography
{
    public class ProtectedAesProvider : ICryptoServiceOwner
    {
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

        public ProtectedMemory DecryptProtected(ProtectedMemory key, string message)
        {
            Blake2bProtectedCryptoProvider blake2b = new Blake2bProtectedCryptoProvider();
            using ProtectedMemory paddedKey = blake2b.ComputeHashProtected(key, 64);
            ExtractHeader(message, paddedKey, out byte[] iv, out byte[] messageBytes);
            using ProtectedMemory protectedBuffer = ProtectedMemory.Allocate(messageBytes.Length);
            protectedBuffer.Write(messageBytes, 0, messageBytes.Length);
            using (ProtectedMemory aesKey = DeriveAesKey(paddedKey))
            {
                AesState aesState = new AesState(aesKey, iv);
                aesState.AesCbcDecryptBuffer(protectedBuffer);
            }
            int contentLength = Pkcs7Padding.GetContentLength(protectedBuffer, 16);
            ProtectedMemory result = ProtectedMemory.Allocate(contentLength);
            protectedBuffer.CopyTo(0, result, 0, contentLength);
            return result;
        }

        public string Decrypt(ProtectedMemory key, string message)
        {
            Blake2bProtectedCryptoProvider blake2b = new Blake2bProtectedCryptoProvider();
            using ProtectedMemory paddedKey = blake2b.ComputeHashProtected(key, 64);
            ExtractHeader(message, paddedKey, out byte[] iv, out byte[] buffer);
            using (ProtectedMemory aesKey = DeriveAesKey(paddedKey))
            {
                AesState aesState = new AesState(aesKey, iv);
                aesState.AesCbcDecryptBuffer(ref buffer);
            }
            int contentLength = Pkcs7Padding.GetContentLength(buffer, 16);
            return Encoding.UTF8.GetString(buffer, 0, contentLength);
        }

        private void ExtractHeader(string message, ProtectedMemory paddedKey, out byte[] iv, out byte[] messageBytes)
        {
            byte[] rawMessageBytes = Convert.FromBase64String(message);
            iv = rawMessageBytes[0..16];
            byte[] hmac = rawMessageBytes[^64..];
            messageBytes = rawMessageBytes[16..^64];
            using ProtectedMemory hmacKey = DeriveHmacKey(paddedKey);
            byte[] aesResult = rawMessageBytes[..^64];
            Blake2bProtectedCryptoProvider blake2b = new Blake2bProtectedCryptoProvider();
            byte[] actualHmac = blake2b.CalculateHmac(hmacKey, aesResult); // don't forget the IV
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

        public string EncryptProtected(ProtectedMemory key, ProtectedMemory message)
        {
            Blake2bProtectedCryptoProvider blake2b = new Blake2bProtectedCryptoProvider();
            using ProtectedMemory paddedKey = blake2b.ComputeHashProtected(key, 64);
            byte[] iv = new byte[16];
            ICryptoServiceOwner.RngCryptoService.GetBytes(iv);
            using ProtectedMemory protectedBuffer = ProtectedMemory.Allocate(message.ContentLength + 16 - (message.ContentLength & 0xF));
            message.CopyTo(0, protectedBuffer, 0, message.ContentLength);
            Pkcs7Padding.Apply(protectedBuffer, (uint)message.ContentLength, 16);
            using (ProtectedMemory aesKey = DeriveAesKey(paddedKey))
            {
                AesState aesState = new AesState(aesKey, iv);
                aesState.AesCbcEncryptBuffer(protectedBuffer);
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

        public string Encrypt(ProtectedMemory key, string message)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            Blake2bProtectedCryptoProvider blake2b = new Blake2bProtectedCryptoProvider();
            using ProtectedMemory paddedKey = blake2b.ComputeHashProtected(key, 64);
            byte[] iv = new byte[16];
            ICryptoServiceOwner.RngCryptoService.GetBytes(iv);
            byte[] buffer = new byte[messageBytes.Length + 16 - (messageBytes.Length & 0xF)];
            Buffer.BlockCopy(messageBytes, 0, buffer, 0, messageBytes.Length);
            Pkcs7Padding.Apply(buffer, (uint)messageBytes.Length, 16);
            using (ProtectedMemory aesKey = DeriveAesKey(paddedKey))
            {
                AesState aesState = new AesState(aesKey, iv);
                aesState.AesCbcEncryptBuffer(ref buffer);
            }
            byte[] aesResult = new byte[buffer.Length + 16];
            Buffer.BlockCopy(iv, 0, aesResult, 0, 16);
            Buffer.BlockCopy(buffer, 0, aesResult, 16, buffer.Length);
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
