using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X.Security.MemoryProtection
{
    internal class ProtectedListNode : IDisposable
    {
        public virtual ProtectedMemory Value { get; }

        internal ProtectedListNode(int size)
        {
            Value = ProtectedMemory.Allocate(size);
        }

        public ProtectedListNode Previous { get; set; }
        public ProtectedListNode Next { get; set; }

        public void Dispose()
        {
            Value.Free();
        }

        public bool Equals(ProtectedListNode other)
        {
            return Value.Equals(other);
        }
    }
}
