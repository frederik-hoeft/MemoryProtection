using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X.Security.Defense
{
    internal static class DebugDetector
    {
        // Check for managed debuggers ...
        internal static bool DebuggerIsAttached => System.Diagnostics.Debugger.IsAttached;
    }
}
