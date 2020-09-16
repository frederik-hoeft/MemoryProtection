using System;
using System.Collections.Generic;
using System.Text;

namespace MemoryProtection
{
    internal static class DebugDetector
    {
        // Check for managed debuggers ...
        internal static bool DebuggerIsAttached => System.Diagnostics.Debugger.IsAttached;
    }
}
