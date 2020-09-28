using MemoryProtection.MemoryProtection;
using MemoryProtection.MemoryProtection.Cryptography;
using MemoryProtection.MemoryProtection.Cryptography.Aes256Protected;
using MemoryProtection.MemoryProtection.Cryptography.Blake2bProtected;
using MemoryProtection.MemoryProtection.Cryptography.ScryptProtected;
using MemoryProtection.MemoryProtection.Cryptography.Sha256Protected;
using MemoryProtection.MemoryProtection.ProtectedString;
using MemoryProtection.MemoryProtection.Win32;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            // Call whatever test method you want.
            AesTests2();
        }

        private static void AesTests2()
        {
            byte[] key = Encoding.UTF8.GetBytes("ABCD");
            using ProtectedMemory protectedKey = ProtectedMemory.Allocate(key.Length);
            protectedKey.Write(key, 0);
            ProtectedAesProvider aes = new ProtectedAesProvider();
            const string secret = "ABCDDCBA";
            Console.WriteLine("Original message:");
            Console.WriteLine(secret + "\n");
            string encrypted = aes.Encrypt(protectedKey, secret);
            Console.WriteLine("Encrypted message:");
            Console.WriteLine(encrypted + "\n");
            string decrypted = aes.Decrypt(protectedKey, encrypted);
            Console.WriteLine("Decrypted message:");
            Console.WriteLine(decrypted + "\n");
        }

        private static void AesTests()
        {
            byte[] key = Encoding.UTF8.GetBytes("ABCD");
            using ProtectedMemory protectedKey = ProtectedMemory.Allocate(key.Length);
            protectedKey.Write(key, 0);
            ProtectedAesProvider aes = new ProtectedAesProvider();
            const string secret = "0123456789ABCDEF";
            Console.WriteLine("Original message:");
            Console.WriteLine(secret + "\n");
            byte[] message = Encoding.UTF8.GetBytes(secret);
            using ProtectedMemory protectedMessage = ProtectedMemory.Allocate(message.Length);
            protectedMessage.Write(message, 0);
            string encrypted = aes.EncryptProtected(protectedKey, protectedMessage);
            Console.WriteLine("Encrypted message:");
            Console.WriteLine(encrypted + "\n");
            using ProtectedMemory protectedResult = aes.DecryptProtected(protectedKey, encrypted);
            byte[] result = protectedResult.Read(0, message.Length);
            Console.WriteLine("Decrypted message:");
            Console.WriteLine(Encoding.UTF8.GetString(result) + "\n");
        }

        private static void Sha256HmacPerfTest()
        {
            byte[] key = Encoding.UTF8.GetBytes("ABCD");
            byte[] message = Encoding.UTF8.GetBytes("ABCD");
            using ProtectedMemory protectedKey = ProtectedMemory.Allocate(key.Length);
            using ProtectedMemory protectedMessage = ProtectedMemory.Allocate(message.Length);
            protectedKey.Write(key, 0);
            protectedMessage.Write(message, 0);
            Sha256ProtectedCryptoProvider sha256 = new Sha256ProtectedCryptoProvider();
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            for (int i = 0; i < 250000; i++)
            {
                _ = sha256.ComputeHmac(protectedKey, protectedMessage);
            }
            stopwatch.Stop();
            Console.WriteLine("250000 HMACs done in " + stopwatch.Elapsed.ToString());
            double t = stopwatch.ElapsedMilliseconds / 250000d;
            Console.WriteLine(" * " + t.ToString() + " ms per HMAC.");
            Console.WriteLine(" * " + (1000d / t).ToString() + " HMACs per second.");
        }

        private static void ScryptPerfTest()
        {
            byte[] bytes = Encoding.UTF8.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
            using ProtectedMemory protectedMemory = ProtectedMemory.Allocate(bytes.Length);
            protectedMemory.Write(bytes, 0);
            ScryptProtectedCryptoProvider scryptProtected = new ScryptProtectedCryptoProvider();
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            for (int i = 0; i < 20; i++)
            {
                _ = scryptProtected.ComputeHash(protectedMemory);
            }
            stopwatch.Stop();
            Console.WriteLine("20 hashes done in " + stopwatch.Elapsed.ToString());
            double t = stopwatch.ElapsedMilliseconds / 20d;
            Console.WriteLine(" * " + t.ToString() + " ms per digest.");
            Console.WriteLine(" * " + (1000d / t).ToString() + " hashes per second.");
        }

        private static void ScryptTests()
        {
            // Iterations:  65536
            // blockSize:   8
            // Threads:     1
            // SALT: TB5ny6LI9KywU3+TD5FdrNSsxYV2T+3qyxRwMieu7zQ=
            // HASH: +jsi778vVLkfYWp3dQDwW7g9/XMySal9lDoEQxvB6uc=

            byte[] bytes = Encoding.UTF8.GetBytes("ABCD");
            ProtectedMemory protectedMemory = ProtectedMemory.Allocate(bytes.Length);
            protectedMemory.Write(bytes, 0);
            // ScryptProtectedCryptoProvider scryptProtected2 = new ScryptProtectedCryptoProvider();
            // Console.WriteLine(scryptProtected2.ComputeHash(protectedMemory, Convert.FromBase64String("TB5ny6LI9KywU3+TD5FdrNSsxYV2T+3qyxRwMieu7zQ="), 65536, 8, 1, 32));
            byte[] bytes2 = Encoding.UTF8.GetBytes("DCBA");
            ProtectedMemory protectedMemory2 = ProtectedMemory.Allocate(bytes.Length);
            protectedMemory2.Write(bytes2, 0);
            ScryptProtectedCryptoProvider scryptProtected = new ScryptProtectedCryptoProvider();
            string result = scryptProtected.ComputeHash(protectedMemory);
            Console.WriteLine(result);
            Console.WriteLine("Should be False:");
            Console.WriteLine(scryptProtected.Compare(protectedMemory2, result));
            Console.WriteLine("Should be True:");
            Console.WriteLine(scryptProtected.Compare(protectedMemory, result));
        }

        private static void Blake2PerfTest()
        {
            byte[] bytes = Encoding.UTF8.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
            using ProtectedMemory protectedMemory = ProtectedMemory.Allocate(bytes.Length);
            protectedMemory.Write(bytes, 0);
            Blake2bProtectedCryptoProvider blake2 = new Blake2bProtectedCryptoProvider();
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            for (int i = 0; i < 1000000; i++)
            {
                _ = blake2.ComputeHash(protectedMemory);
            }
            stopwatch.Stop();
            Console.WriteLine("1000000 hashes done in " + stopwatch.Elapsed.ToString());
            double t = stopwatch.ElapsedMilliseconds / 1000000d;
            Console.WriteLine(" * " + t.ToString() + " ms per digest.");
            Console.WriteLine(" * " + (1000d / t).ToString() + " hashes per second.");
        }

        private static void Blake2Tests()
        {
            const string input = "ABCD";
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            using ProtectedMemory protectedMemory = ProtectedMemory.Allocate(bytes.Length);
            protectedMemory.Write(bytes, 0);
            Blake2bProtectedCryptoProvider blake2 = new Blake2bProtectedCryptoProvider();
            Console.WriteLine(blake2.ComputeHash(protectedMemory));
        }

        private static unsafe void Sha256HmacTests2()
        {
            byte[] key = Encoding.UTF8.GetBytes("ABCD");
            IntPtr hMessage = Marshal.AllocHGlobal(32 + sizeof(int));
            byte[] message = new byte[] { 0x4c, 0x1e, 0x67, 0xcb, 0xa2, 0xc8, 0xf4, 0xac, 0xb0, 0x53, 0x7f, 0x93, 0xf, 0x91, 0x5d, 0xac, 0xd4, 0xac, 0xc5, 0x85, 0x76, 0x4f, 0xed, 0xea, 0xcb, 0x14, 0x70, 0x32, 0x27, 0xae, 0xef, 0x34, 0x0, 0x0, 0x0, 0x0 };
            Marshal.Copy(message, 0, hMessage, message.Length);
            fixed (byte* pKey = key)
            {
                byte* pMessage = (byte*)hMessage;
                Sha256ProtectedCryptoProvider sha256 = new Sha256ProtectedCryptoProvider();
                (IntPtr h, int l) = sha256.ComputeHmacUnsafe(pKey, 4, pMessage, 32 + sizeof(int));
                Marshal.FreeHGlobal(h);
            }
            Marshal.FreeHGlobal(hMessage);
        }

        private static void Sha256HmacTests()
        {
            byte[] key = Encoding.UTF8.GetBytes("ABCD");
            byte[] message = Encoding.UTF8.GetBytes("ABCD");
            using ProtectedMemory protectedKey = ProtectedMemory.Allocate(key.Length);
            using ProtectedMemory protectedMessage = ProtectedMemory.Allocate(message.Length);
            protectedKey.Write(key, 0);
            protectedMessage.Write(message, 0);
            Sha256ProtectedCryptoProvider sha256 = new Sha256ProtectedCryptoProvider();
            Console.WriteLine(sha256.ComputeHmac(protectedKey, protectedMessage));
        }

        private static void Sha256PerfTest()
        {
            byte[] bytes = Encoding.UTF8.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
            using ProtectedMemory protectedMemory = ProtectedMemory.Allocate(bytes.Length);
            protectedMemory.Write(bytes, 0);
            Sha256ProtectedCryptoProvider sha256 = new Sha256ProtectedCryptoProvider();
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            for (int i = 0; i < 500000; i++)
            {
                _ = sha256.ComputeHash(protectedMemory);
            }
            stopwatch.Stop();
            Console.WriteLine("500000 hashes done in " + stopwatch.Elapsed.ToString());
            double t = stopwatch.ElapsedMilliseconds / 500000d;
            Console.WriteLine(" * " + t.ToString() + " ms per digest.");
            Console.WriteLine(" * " + (1000d / t).ToString() + " hashes per second.");
        }

        private static unsafe void Sha256Tests()
        {
            byte[] bytes = Encoding.UTF8.GetBytes("ABCD");
            using ProtectedMemory protectedMemory = ProtectedMemory.Allocate(bytes.Length);
            protectedMemory.Write(bytes, 0);
            Sha256ProtectedCryptoProvider sha256 = new Sha256ProtectedCryptoProvider();
            Console.WriteLine(sha256.ComputeHash(protectedMemory));
            fixed (byte* b = bytes)
            {
                Console.WriteLine(sha256.ComputeHashUnsafe(b, bytes.Length));
            }
        }

        private static void ShiftingTest()
        {
            ProtectedMemory protectedMemory = ProtectedMemory.Allocate(8);
            byte[] bytes = new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };
            protectedMemory.Write(bytes, 0);
            PrintArray(protectedMemory.Read(0, protectedMemory.ContentLength));
            Console.ReadLine();
            Console.WriteLine("Shifting 1 byte right");
            protectedMemory >>= 1;
            PrintArray(protectedMemory.Read(0, protectedMemory.ContentLength));
            Console.ReadLine();
            Console.WriteLine("Shifting 1 byte left");
            protectedMemory <<= 1;
            PrintArray(protectedMemory.Read(0, protectedMemory.ContentLength));
            Console.ReadLine();
            Console.WriteLine("Shifting 1 byte left");
            protectedMemory <<= 1;
            PrintArray(protectedMemory.Read(0, protectedMemory.ContentLength));
            Console.ReadLine();
        }

        private static void TestProtectedStringList()
        {
            Console.WriteLine("This is a linked list with each character being of type ProtectedMemory. During comparison only a single character will be unprotected.");
            Console.WriteLine("Try finding correct the password using memory operations only. No hashing involved here. Only comparisons ...");
            using IProtectedString target = new ProtectedStringList();
            target.Append('S');
            target.Append('e');
            target.Append('c');
            target.Append('r');
            target.Append('e');
            target.Append('t');
            while (true)
            {
                ConsoleKeyInfo info;
                using IProtectedString protectedString = new ProtectedStringList();
                while ((info = Console.ReadKey()).Key != ConsoleKey.Enter)
                {
                    protectedString.Append(info.KeyChar);
                }
                Console.WriteLine("");
                if (protectedString.Equals(target))
                {
                    Console.WriteLine("----------------------------------");
                    Console.WriteLine("            Correct :)");
                    Console.WriteLine("----------------------------------");
                }
                else
                {
                    Console.WriteLine("----------------------------------");
                    Console.WriteLine("             Nope :|");
                    Console.WriteLine("----------------------------------");
                }
            }
        }

        private static void TestProtectedStringBlock()
        {
            Console.WriteLine("This is a continuous region of ProtectedMemory. During comparison the whole thing will be unprotected.");
            Console.WriteLine("Try finding correct the password using memory operations only. No hashing involved here. Only comparisons ...");
            using IProtectedString target = new ProtectedStringBlock();
            target.Append('S');
            target.Append('e');
            target.Append('c');
            target.Append('r');
            target.Append('e');
            target.Append('t');
            while (true)
            {
                ConsoleKeyInfo info;
                using IProtectedString protectedString = new ProtectedStringBlock();
                while ((info = Console.ReadKey()).Key != ConsoleKey.Enter)
                {
                    protectedString.Append(info.KeyChar);
                }
                Console.WriteLine("");
                if (protectedString.Equals(target))
                {
                    Console.WriteLine("----------------------------------");
                    Console.WriteLine("            Correct :)");
                    Console.WriteLine("----------------------------------");
                }
                else
                {
                    Console.WriteLine("----------------------------------");
                    Console.WriteLine("             Nope :|");
                    Console.WriteLine("----------------------------------");
                }
            }
        }

        private static void TestProtectedMemory()
        {
            using ProtectedMemory protectedMemory = new Win32EncryptedMemory(8);
            protectedMemory[0] = Encoding.ASCII.GetBytes("S")[0];
            protectedMemory[1] = Encoding.ASCII.GetBytes("e")[0];
            protectedMemory[2] = Encoding.ASCII.GetBytes("c")[0];
            protectedMemory[3] = Encoding.ASCII.GetBytes("r")[0];
            protectedMemory[4] = Encoding.ASCII.GetBytes("e")[0];
            protectedMemory[5] = Encoding.ASCII.GetBytes("t")[0];
            protectedMemory.Unprotect();
            Console.WriteLine("Unprotected!");
            Console.ReadLine();
            protectedMemory.Protect();
            Console.WriteLine("Protected!");
            Console.ReadLine();
            protectedMemory.Unprotect();
            Console.WriteLine("Unprotected!");
            Console.ReadLine();
            protectedMemory.Protect();
            Console.WriteLine("Protected!");
            Console.ReadLine();
            protectedMemory.Free();
            Console.WriteLine("Freed!");
            Console.ReadLine();
        }

        private static void TestProtectedMemory2()
        {
            using ProtectedMemory protectedMemory = ProtectedMemory.Allocate(8);
            protectedMemory[0] = 0x1;
            PrintArray(protectedMemory.Read(0, 8));
            protectedMemory[1] = 0x3;
            PrintArray(protectedMemory.Read(0, 8));
            protectedMemory[2] = 0x3;
            PrintArray(protectedMemory.Read(0, 8));
            protectedMemory[3] = 0x7;
            PrintArray(protectedMemory.Read(0, 8));
            protectedMemory[0] = 0x8;
            Console.ReadLine();
            protectedMemory.Protect();
            Console.WriteLine("Protected!");
            Console.ReadLine();
            protectedMemory.Unprotect();
            Console.WriteLine("Unprotected!");
            Console.ReadLine();
            protectedMemory.Protect();
            Console.WriteLine("Protected!");
            byte[] bytes = new byte[8];
            Console.WriteLine("Trying to access protected memory (should fail)");
            Console.ReadLine();
#pragma warning disable CS0618 // Type or member is obsolete
            Marshal.Copy(protectedMemory.GetDirectHandle(), bytes, 0, bytes.Length);
#pragma warning restore CS0618 // Type or member is obsolete
            PrintArray(bytes);
        }

        internal static void PrintArray(byte[] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                Console.Write("0x" + arr[i].ToString("x") + " ");
            }
            Console.WriteLine("");
        }

        internal static unsafe void PrintArray(IntPtr ptr, int size)
        {
            PrintArray((byte*)ptr, size);
        }

        internal static unsafe void PrintArray(byte* bytes, int size)
        {
            for (int i = 0; i < size; i++)
            {
                Console.Write("0x" + bytes[i].ToString("x") + " ");
            }
            Console.WriteLine("");
        }

        internal static unsafe void PrintArray(byte* bytes, uint size)
        {
            for (int i = 0; i < size; i++)
            {
                Console.Write("0x" + bytes[i].ToString("x") + " ");
            }
            Console.WriteLine("");
        }

        internal static void PrintInt32Array(IntPtr ptr, int size)
        {
            for (int i = 0; i < size / sizeof(int); i++)
            {
                Console.Write(Marshal.ReadInt32(ptr + i * sizeof(int)).ToString() + " ");
            }
            Console.WriteLine("");
        }

        internal static unsafe void PrintUInt64Array(ulong* ptr, int size)
        {
            for (int i = 0; i < size; i++)
            {
                Console.Write(ptr[i].ToString() + " ");
            }
            Console.WriteLine("");
        }

        internal static void PrintInt32BigEndianArray(IntPtr ptr, int size)
        {
            for (int i = 0; i < size / sizeof(int); i++)
            {
                Console.Write(MarshalExtensions.ReadInt32BigEndian(ptr + (i * sizeof(int))).ToString() + " ");
            }
            Console.WriteLine("");
        }

        private static bool TestDebugDetection()
        {
            bool isDebug1 = Win32DebugDetector.CheckProcessDebugFlags();
            bool isDebug2 = Win32DebugDetector.CheckDebugObjectExists();
            bool isDebug3 = Win32DebugDetector.CheckOutputDebugString();
            bool isDebug4 = DebugDetector.DebuggerIsAttached;
            bool isDebug5 = Win32DebugDetector.CanOpenCsrss();
            bool isDebug6 = Win32DebugDetector.CheckIsDebuggerPresent();
            Console.WriteLine("CheckProcessDebugFlags: " + isDebug1.ToString());
            Console.WriteLine("CheckDebugObjectExists: " + isDebug2.ToString());
            Console.WriteLine("CheckOutputDebugString: " + isDebug3.ToString());
            Console.WriteLine("DebuggerIsAttached: " + isDebug4.ToString());
            Console.WriteLine("CanOpenCsrss: " + isDebug5.ToString());
            Console.WriteLine("CheckIsDebuggerPresent: " + isDebug6.ToString());
            Console.WriteLine("Debugger Detected: " + (isDebug1 || isDebug2 || isDebug3 || isDebug4 || isDebug6).ToString());
            Console.WriteLine("-------------------------------------------------------");
            return isDebug1 || isDebug2 || isDebug3 || isDebug4 || isDebug6;
        }
    }
}
