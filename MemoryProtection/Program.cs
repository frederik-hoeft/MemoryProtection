using MemoryProtection.SelfProtection;
using MemoryProtection.SelfProtection.MemoryProtection;
using MemoryProtection.SelfProtection.MemoryProtection.ProtectedString;
using MemoryProtection.SelfProtection.MemoryProtection.Win32;
using System;
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
            TestProtectedStringList();
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
