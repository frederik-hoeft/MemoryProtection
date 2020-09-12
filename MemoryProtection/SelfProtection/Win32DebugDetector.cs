using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.SelfProtection
{
    internal static class Win32DebugDetector
    {
        [DllImport("ntdll.dll", PreserveSig = false, SetLastError = true)]
        internal static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, out uint processInformation, uint ProcessInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", PreserveSig = false, SetLastError = true)]
        internal static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, out ulong processInformation, uint ProcessInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength, out uint ReturnLength);

        [DllImport("Kernel32.dll", SetLastError = true, PreserveSig = false, CharSet = CharSet.Unicode)]
        internal static extern void OutputDebugStringA(string lpOutputString);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(ProcessPermission processPermission,bool bInheritHandle,int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsDebuggerPresent();

        [Flags]
        public enum ProcessPermission : uint
        {
            PROCESS_ALL_ACCESS = 0x1F0FFF,
            PROCESS_TERMINATE = 0x0001,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_SET_SESSIONID = 0x0004,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            END = 0xFFF
        }

        // CheckProcessDebugFlags will return true if
        // the EPROCESS->NoDebugInherit is == FALSE,
        // the reason we check for false is because
        // the NtQueryProcessInformation function returns the
        // inverse of EPROCESS->NoDebugInherit so (!TRUE == FALSE)
        internal static bool CheckProcessDebugFlags()
        {
            int status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0x1f, out uint noDebugInherit, sizeof(uint), out _);
            if (status != 0x00000000)
            {
                return false;
            }
            return noDebugInherit == 0x0;
        }

        // This function uses NtQuerySystemInformation
        // to try to retrieve a handle to the current
        // process's debug object handle. If the function
        // is successful it'll return true which means we're
        // being debugged or it'll return false if it fails
        // or the process isn't being debugged
        internal static bool CheckDebugObjectExists()
        {
            // IntPtr hDebugObject = IntPtr.Zero;
            int status = 0x00000000;
            ulong hDebugObject = 0x0;
            try
            {
                status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0x1e, out hDebugObject, sizeof(ulong), out _);
            }
            catch (COMException e) when ((uint)e.ErrorCode == 0xC0000353)
            {
                return false;
            }
            if (status != 0x00000000)
            {
                return false;
            }
            return hDebugObject != 0x0;
        }

        // CheckOutputDebugString checks whether or
        // OutputDebugString causes an error to occur
        // and if the error does occur then we know
        // there's no debugger, otherwise if there IS
        // a debugger no error will occur
        internal static bool CheckOutputDebugString()
        {
            try
            {
                OutputDebugStringA(string.Empty);
                return true;
            }
            catch (COMException)
            {
                return false;
            }
        }

        // The function will attempt to open csrss.exe with
        // PROCESS_ALL_ACCESS rights if it fails we're
        // not being debugged however, if its successful we probably are, or we're just running as Admin. Not really decisive ...
        internal static bool CanOpenCsrss()
        {
            Process p = Process.GetProcessesByName("csrss").FirstOrDefault();
            // If we're being debugged and the process has
            // SeDebugPrivileges privileges then this call
            // will be successful, note that this only works
            // with PROCESS_ALL_ACCESS.
            IntPtr Csrss = OpenProcess(ProcessPermission.PROCESS_ALL_ACCESS, false, p.Id);

            if (Csrss != IntPtr.Zero)
            {
                CloseHandle(Csrss);
                return true;
            }
            else
            {
                return false;
            }
        }

        // Check for native debuggers ...
        internal static bool CheckIsDebuggerPresent()
        {
            return IsDebuggerPresent();
        }
    }
}
