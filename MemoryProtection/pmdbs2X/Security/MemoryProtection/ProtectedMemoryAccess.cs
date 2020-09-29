using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X.Security.MemoryProtection
{
    public class ProtectedMemoryAccess : IDisposable
    {
        private readonly ProtectedMemory pMemory;

        public ProtectedMemoryAccess(ProtectedMemory protectedMemory)
        {
            pMemory = protectedMemory;
            pMemory.Unprotect();
        }

#pragma warning disable CS0618 // Type or member is obsolete
        public IntPtr Handle => pMemory.GetDirectHandle();
#pragma warning restore CS0618 // Type or member is obsolete

        public void Dispose()
        {
            pMemory.Protect();
        }
    }
}
