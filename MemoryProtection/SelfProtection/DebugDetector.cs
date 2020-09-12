using System;
using System.Collections.Generic;
using System.Text;

namespace MemoryProtection.SelfProtection
{
    internal static class DebugDetector
    {
        // Check for managed debuggers ...
        internal static bool DebuggerIsAttached => System.Diagnostics.Debugger.IsAttached;
    }
}
