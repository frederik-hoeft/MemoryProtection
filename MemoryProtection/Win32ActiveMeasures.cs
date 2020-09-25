using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace MemoryProtection
{
    internal static class Win32ActiveMeasures
    {
        private const uint THREAD_SET_INFORMATION = 0x0020;
        private const uint PAGE_READWRITE = 0x04;

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("ntdll.dll", SetLastError = true, PreserveSig = false)]
        internal static extern uint NtSetInformationThread(IntPtr hThread, uint threadInformationClass, IntPtr threadInformation, ulong threadInformationLength);

        [DllImport("kernel32.dll")]
        internal static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        /// <summary>
        /// HideThread will attempt to use
        /// NtSetInformationThread to hide the current thread
        /// from the debugger.
        /// <para>Note: this will also terminate any Visual Studio debugging session.</para>
        /// </summary>
        /// <returns><c>false</c> on failure and <c>true</c> on success.</returns>
        internal static bool HideThread(uint threadId)
        {
            IntPtr hThread = OpenThread(THREAD_SET_INFORMATION, false, threadId);
            // Set the thread info
            uint status = NtSetInformationThread(hThread, 0x11, IntPtr.Zero, 0);
            CloseHandle(hThread);
            return status == 0x00000000;
        }

        // hides all currently running threads from debuggers. Breakpoints will not be hit in Visual Studio ...
        internal static void HideAllThreads()
        {
            foreach (ProcessThread thread in Process.GetCurrentProcess().Threads)
            {
                bool success = HideThread((uint)thread.Id);
                if (success)
                {
                    Console.WriteLine("Thread 0x" + thread.Id.ToString("X") + " is now hidden and cannot be debugged!");
                }
                else
                {
                    Console.WriteLine("Failed to hide thread 0x" + thread.Id.ToString("X") + "!");
                }
            }
        }

        // This function will erase the current images
        // PE header from memory preventing a successful image
        // if dumped
        internal static void ErasePEHeaderFromMemory()
        {
            // Get base address of module
            IntPtr pBaseAddr = Process.GetCurrentProcess().MainModule.BaseAddress;

            // Change memory protection
            bool success = VirtualProtect(pBaseAddr, 4096u, PAGE_READWRITE, out _);

            if (success)
            {
                // Erase the header
                Marshal.Copy(new byte[4096], 0, pBaseAddr, 4096);
            }
        }
    }
}
