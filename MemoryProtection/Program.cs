using MemoryProtection;
using MemoryProtection.MemoryProtection;
using MemoryProtection.MemoryProtection.Cryptography;
using MemoryProtection.MemoryProtection.Cryptography.Sha256Protected;
using MemoryProtection.MemoryProtection.ProtectedString;
using MemoryProtection.MemoryProtection.Win32;
using System;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;

namespace MemoryProtection
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            // Call whatever test method you want.
            Sha256PerfTest();
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

        private static void Sha256Tests()
        {
            byte[] bytes = Encoding.UTF8.GetBytes("ABCD");
            using ProtectedMemory protectedMemory = ProtectedMemory.Allocate(bytes.Length);
            protectedMemory.Write(bytes, 0);
            Sha256ProtectedCryptoProvider sha256 = new Sha256ProtectedCryptoProvider();
            Console.WriteLine(sha256.ComputeHash(protectedMemory));
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
            Console.ReadLine();
            Console.WriteLine("Trying direct read (should fail)");
            byte[] bytes = new byte[8];
            Marshal.Copy(protectedMemory.Handle, bytes, 0, bytes.Length);
            PrintArray(bytes);
        }

        internal static void PrintArray(byte[] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                Console.Write(arr[i].ToString() + " ");
            }
            Console.WriteLine("");
        }

        internal static void PrintArray(IntPtr ptr, int size)
        {
            byte[] bytes = new byte[size];
            Marshal.Copy(ptr, bytes, 0, size);
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
